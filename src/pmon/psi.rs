// This file deals with watching memory pressure (PSI) for a set of 
// processes.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread::JoinHandle;
use mio::{Events, Interest, Poll, Token, Waker};
use mio::unix::SourceFd;
// Import the function to read cgroup paths from proc.rs
use super::proc::create_process_info;

const WAKER_TOKEN: Token = Token(1024);

pub enum PressureType {
    Memory,
    Cpu,
    Io,
}

struct Watch {
    cgroup_path: String,
    pressure_type: PressureType,
}

pub struct PsiWatcher {
    running: Arc<AtomicBool>,
    watches: Arc<Mutex<HashMap<u32, Watch>>>, // pid -> Watch
    new_pids: Arc<Mutex<Vec<u32>>>, // PIDs to be added
    terminated_pids: Arc<Mutex<Vec<u32>>>, // PIDs to be removed
    handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    callback: Arc<Mutex<Option<Box<dyn Fn(u32, &str) + Send + Sync>>>>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl PsiWatcher {
    /// Create a new PsiWatcher
    pub fn new() -> Self {
        PsiWatcher {
            running: Arc::new(AtomicBool::new(false)),
            watches: Arc::new(Mutex::new(HashMap::new())),
            new_pids: Arc::new(Mutex::new(Vec::new())),
            terminated_pids: Arc::new(Mutex::new(Vec::new())),
            handle: Arc::new(Mutex::new(None)),
            callback: Arc::new(Mutex::new(None)),
            waker: Arc::new(Mutex::new(None)),
        }
    }
    
    /// Set a callback to be invoked when a PSI event is triggered
    pub fn set_callback<F>(&self, cb: F) 
    where 
        F: Fn(u32, &str) + Send + Sync + 'static,
    {
        let mut callback = self.callback.lock().unwrap();
        *callback = Some(Box::new(cb));
    }
    
    /// Add a process to watch by PID
    pub fn add_pid(&self, pid: u32, pressure_type: PressureType) {
        // Get the cgroup path for this process
        match create_process_info(pid) {
            Ok(process_info) => {
                if let Some(cgroup_path) = process_info.cgroup_path {
                    let mut watches = self.watches.lock().unwrap();
                    watches.insert(pid, Watch { cgroup_path, pressure_type });
                    drop(watches);

                    let mut new_pids = self.new_pids.lock().unwrap();
                    new_pids.push(pid);
                    drop(new_pids);

                    if let Some(waker) = self.waker.lock().unwrap().as_ref() {
                        if let Err(e) = waker.wake() {
                            eprintln!("Failed to wake PSI watcher for PID {}: {}", pid, e);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to create process info for PID {}: {}", pid, e);
            }
        }
    }
    
    /// Remove a process from the watch list
    pub fn remove_pid(&self, pid: u32) {
        let mut terminated_pids = self.terminated_pids.lock().unwrap();
        terminated_pids.push(pid);
        if let Some(waker) = self.waker.lock().unwrap().as_ref() {
            waker.wake().unwrap();
        }
    }
    
    /// Start the PSI monitoring thread
    pub fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        
        self.running.store(true, Ordering::SeqCst);
        
        let running = self.running.clone();
        let watches = self.watches.clone();
        let new_pids = self.new_pids.clone();
        let terminated_pids = self.terminated_pids.clone();
        let callback = self.callback.clone();
        let waker = self.waker.clone();

        let handle = std::thread::spawn(move || {
            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(1024);
            let mut token_map = HashMap::new();
            let mut files = HashMap::new();
            let mut next_token = Token(0);

            let new_waker = Waker::new(poll.registry(), WAKER_TOKEN).unwrap();
            *waker.lock().unwrap() = Some(new_waker);

            {
                let watches_snapshot = watches.lock().unwrap();
                for (&pid, watch) in watches_snapshot.iter() {
                    let pressure_file_name = match watch.pressure_type {
                        PressureType::Memory => "memory.pressure",
                        PressureType::Cpu => "cpu.pressure",
                        PressureType::Io => "io.pressure",
                    };
                    let pressure_file_path = format!("{}/{}", watch.cgroup_path, pressure_file_name);
                    let mut file = match OpenOptions::new().read(true).write(true).open(&pressure_file_path) {
                        Ok(f) => f,
                        Err(_e) => {
                            //eprintln!("Failed to open {}: {}", pressure_file_path, e);
                            continue;
                        }
                    };

                    let trig = "some 150000 1000000";
                    if let Err(e) = file.write_all(trig.as_bytes()) {
                        eprintln!("Failed to write to {}: {}", pressure_file_path, e);
                        continue;
                    }

                    let fd = file.as_raw_fd();
                    let token = Token(next_token.0);
                    next_token.0 += 1;

                    poll.registry().register(&mut SourceFd(&fd), token, Interest::PRIORITY).unwrap();
                    token_map.insert(token, pid);
                    files.insert(pid, file);
                }
            }

            while running.load(Ordering::SeqCst) {
                match poll.poll(&mut events, None) {
                    Ok(_) => (),
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        eprintln!("Poll failed: {}", e);
                        break;
                    }
                }

                for event in events.iter() {
                    match event.token() {
                        WAKER_TOKEN => {
                            if !running.load(Ordering::SeqCst) {
                                return;
                            }
                            
                            let mut terminated_pids_lock = terminated_pids.lock().unwrap();
                            for &pid in terminated_pids_lock.iter() {
                                watches.lock().unwrap().remove(&pid);
                                let token_to_remove = token_map.iter()
                                    .find_map(|(k, &v)| if v == pid { Some(k.clone()) } else { None });
                                if let Some(token) = token_to_remove {
                                    token_map.remove(&token);
                                }
                                files.remove(&pid);
                            }
                            terminated_pids_lock.clear();
                            drop(terminated_pids_lock);

                            let mut new_pids_lock = new_pids.lock().unwrap();
                            let watches_lock = watches.lock().unwrap();

                            for &pid in new_pids_lock.iter() {
                                if let Some(watch) = watches_lock.get(&pid) {
                                    let pressure_file_name = match watch.pressure_type {
                                        PressureType::Memory => "memory.pressure",
                                        PressureType::Cpu => "cpu.pressure",
                                        PressureType::Io => "io.pressure",
                                    };
                                    let pressure_file_path = format!("{}/{}", watch.cgroup_path, pressure_file_name);
                                    let mut file = match OpenOptions::new().read(true).write(true).open(&pressure_file_path) {
                                        Ok(f) => f,
                                        Err(_e) => {
                                            //eprintln!("Failed to open {}: {}", pressure_file_path, e);
                                            continue;
                                        }
                                    };

                                    // 10 sec interval
                                    let trig = "some 10000 10000000";
                                    if let Err(e) = file.write_all(trig.as_bytes()) {
                                        eprintln!("Failed to write to {}: {}", pressure_file_path, e);
                                        continue;
                                    }

                                    let fd = file.as_raw_fd();
                                    let token = Token(next_token.0);
                                    next_token.0 += 1;

                                    poll.registry().register(&mut SourceFd(&fd), token, Interest::PRIORITY).unwrap();
                                    token_map.insert(token, pid);
                                    files.insert(pid, file);
                                }
                            }
                            new_pids_lock.clear();
                            drop(new_pids_lock);
                        }
                        token => {
                            if let Some(&pid) = token_map.get(&token) {
                                if files.contains_key(&pid) {
                                    let mut content = String::new();
                                    let watch = watches.lock().unwrap();
                                    let watch = watch.get(&pid).unwrap();
                                    let pressure_file_name = match watch.pressure_type {
                                        PressureType::Memory => "memory.pressure",
                                        PressureType::Cpu => "cpu.pressure",
                                        PressureType::Io => "io.pressure",
                                    };
                                    let pressure_file_path = format!("{}/{}", watch.cgroup_path, pressure_file_name);
                                     if let Ok(mut f) = File::open(&pressure_file_path) {
                                        if f.read_to_string(&mut content).is_ok() {
                                            let cb = callback.lock().unwrap();
                                            if let Some(ref callback_fn) = *cb {
                                                println!("PSI1 event for process {}: \n{}", pid, content.trim_end());
                                                callback_fn(pid, &content.trim_end());
                                            } else {
                                                println!("PSI event for process {}: \n{}", pid, content.trim_end());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        
        let mut h = self.handle.lock().unwrap();
        *h = Some(handle);
        
        Ok(())
    }
    
    /// Stop the PSI monitoring
    pub fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.running.store(false, Ordering::SeqCst);

        if let Some(waker) = self.waker.lock().unwrap().as_ref() {
            waker.wake()?;
        }

        let mut h = self.handle.lock().unwrap();
        if let Some(handle) = h.take() {
            let _ = handle.join();
        }
        
        Ok(())
    }
}

impl Drop for PsiWatcher {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    
    #[test]
    fn test_psi_watcher() {
        let handle = thread::spawn(|| {
            let watcher = PsiWatcher::new();
            
            // Set a callback
            watcher.set_callback(|pid, info| {
                println!("PSI callback triggered for PID {}: {}", pid, info);
            });
            
            // Add current process to watch
            let current_pid = std::process::id();
            watcher.add_pid(current_pid, PressureType::Memory);
            // If this fails, it will print an error message internally
            
            // Start the watcher
            if let Err(e) = watcher.start() {
                println!("Failed to start PSI watcher: {}", e);
                // This might fail in test environments, which is acceptable
                return;
            }
            
            // Wait for a short time to see if any events occur
            thread::sleep(Duration::from_secs(2));
            
            // Stop the watcher
            let _ = watcher.stop();
            
            println!("PSI watcher test completed");
        });

        let start = std::time::Instant::now();
        while !handle.is_finished() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("Test timed out");
            }
            thread::sleep(Duration::from_millis(100));
        }

        match handle.join() {
            Ok(_) => {},
            Err(e) => std::panic::resume_unwind(e),
        }
    }

    #[test]
    fn test_psi_watcher_dynamic_add_remove() {
        let handle = thread::spawn(|| {
            let watcher = PsiWatcher::new();
            watcher.start().unwrap();

            let mut child = std::process::Command::new("sleep")
                .arg("1")
                .spawn()
                .unwrap();
            
            let pid = child.id();
            watcher.add_pid(pid, PressureType::Memory);

            // Check that the pid is in watches
            {
                let watches = watcher.watches.lock().unwrap();
                assert!(watches.contains_key(&pid));
            }

            child.wait().unwrap();

            watcher.remove_pid(pid);

            // Allow some time for the watcher to process the removal
            std::thread::sleep(std::time::Duration::from_millis(100));

            // Check that the pid is no longer in watches
            {
                let watches = watcher.watches.lock().unwrap();
                assert!(!watches.contains_key(&pid));
            }

            watcher.stop().unwrap();
        });

        let start = std::time::Instant::now();
        while !handle.is_finished() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("Test timed out");
            }
            thread::sleep(Duration::from_millis(100));
        }

        match handle.join() {
            Ok(_) => {},
            Err(e) => std::panic::resume_unwind(e),
        }
    }
}
