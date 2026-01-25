/// Watching pressure (PSI) for a set of processes. The list is updated periodically
/// or by using netlink or manually.
use crate::{create_process_info, PressureType};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use tokio::sync::broadcast;
use tracing::{debug, error, info, instrument, trace};

const WAKER_TOKEN: Token = Token(1024);

#[derive(Debug, Clone, serde::Serialize)]
pub struct PressureEvent {
    pub pid: u32,
    pub pressure_type: PressureType,
    pub pressure_data: String,
}

pub struct Watch {
    pub cgroup_path: String,
    pub pressure_type: PressureType,
}
pub struct PsiWatcher {
    running: Arc<AtomicBool>,
    pub watches: Arc<Mutex<HashMap<u32, Watch>>>,
    new_pids: Arc<Mutex<Vec<u32>>>,
    terminated_pids: Arc<Mutex<Vec<u32>>>,
    handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    callback: Arc<Mutex<Option<Box<dyn Fn(u32, &str) + Send + Sync>>>>,
    waker: Arc<Mutex<Option<Waker>>>,
    pub event_tx: broadcast::Sender<PressureEvent>,
    pub interval_us: u64,
    pub threshold_us: u64,
}

impl PsiWatcher {
    /// Create a new PsiWatcher
    #[instrument]
    pub fn new() -> Self {
        debug!("Creating new PsiWatcher");
        let (event_tx, _event_rx) = broadcast::channel(100);
        let watcher = PsiWatcher {
            running: Arc::new(AtomicBool::new(false)),
            watches: Arc::new(Mutex::new(HashMap::new())),
            new_pids: Arc::new(Mutex::new(Vec::new())),
            terminated_pids: Arc::new(Mutex::new(Vec::new())),
            handle: Arc::new(Mutex::new(None)),
            callback: Arc::new(Mutex::new(None)),
            waker: Arc::new(Mutex::new(None)),
            event_tx,
            interval_us: 10000,
            threshold_us: 10000000,
        };
        info!("PsiWatcher created successfully");
        watcher
    }

    /// Update configuration
    pub fn with_config(mut self, interval_us: u64, threshold_us: u64) -> Self {
        self.interval_us = interval_us;
        self.threshold_us = threshold_us;
        self
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
    #[instrument(skip(self), fields(pid = pid))]
    pub fn add_pid(&self, pid: u32, pressure_type: PressureType) {
        debug!(
            "Adding process {} to PSI watcher for {:?}",
            pid, pressure_type
        );
        match create_process_info(pid) {
            Ok(process_info) => {
                if let Some(cgroup_path) = process_info.cgroup_path {
                    trace!("Found cgroup path for PID {}: {}", pid, cgroup_path);
                    let mut watches = self.watches.lock().unwrap();
                    watches.insert(
                        pid,
                        Watch {
                            cgroup_path,
                            pressure_type,
                        },
                    );
                    drop(watches);

                    let mut new_pids = self.new_pids.lock().unwrap();
                    new_pids.push(pid);
                    drop(new_pids);

                    if let Some(waker) = self.waker.lock().unwrap().as_ref() {
                        if let Err(e) = waker.wake() {
                            debug!("Failed to wake PSI watcher for PID {}: {}", pid, e);
                        } else {
                            debug!("Process {} added to PSI watcher", pid);
                        }
                    }
                } else {
                    debug!("No cgroup path found for PID {}, skipping", pid);
                }
            }
            Err(e) => {
                debug!("Failed to create process info for PID {}: {}", pid, e);
            }
        }
    }

    /// Remove a process from the watch list
    #[instrument(skip(self), fields(pid = pid))]
    pub fn remove_pid(&self, pid: u32) {
        trace!("Removing process {} from PSI watcher", pid);
        let mut terminated_pids = self.terminated_pids.lock().unwrap();
        terminated_pids.push(pid);
        if let Some(waker) = self.waker.lock().unwrap().as_ref() {
            if let Err(e) = waker.wake() {
                error!("Failed to wake PSI watcher for PID {}: {}", pid, e);
            }
        }
        trace!("Process {} removed from PSI watcher", pid);
    }

    /// Start the PSI monitoring thread
    #[instrument(skip(self))]
    pub fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Starting PSI monitoring thread");
        if self.running.load(Ordering::SeqCst) {
            debug!("PSI monitoring already running");
            return Ok(());
        }

        self.running.store(true, Ordering::SeqCst);
        info!("PSI monitoring started");

        let running = self.running.clone();
        let watches = self.watches.clone();
        let new_pids = self.new_pids.clone();
        let terminated_pids = self.terminated_pids.clone();
        let callback = self.callback.clone();
        let waker = self.waker.clone();
        let event_tx = self.event_tx.clone();
        let interval_us = self.interval_us;
        let threshold_us = self.threshold_us;

        let handle = std::thread::spawn(move || {
            debug!("PSI monitoring thread started");
            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(1024);
            let mut token_map = HashMap::new();
            let mut files = HashMap::new();
            let mut next_token = Token(0);

            let new_waker = Waker::new(poll.registry(), WAKER_TOKEN).unwrap();
            *waker.lock().unwrap() = Some(new_waker);

            {
                let watches_snapshot = watches.lock().unwrap();
                info!(
                    "Setting up watches for {} processes",
                    watches_snapshot.len()
                );
                for (&pid, watch) in watches_snapshot.iter() {
                    trace!("Setting up watch for PID: {}", pid);
                    let pressure_file_name = match watch.pressure_type {
                        PressureType::Memory => "memory.pressure",
                        PressureType::Cpu => "cpu.pressure",
                        PressureType::Io => "io.pressure",
                    };
                    let pressure_file_path =
                        format!("{}/{}", watch.cgroup_path, pressure_file_name);
                    let mut file = match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&pressure_file_path)
                    {
                        Ok(f) => f,
                        Err(_e) => {
                            continue;
                        }
                    };

                    let trig = format!("some {} {}", interval_us, threshold_us);
                    if let Err(e) = file.write_all(trig.as_bytes()) {
                        error!("Failed to write to {}: {}", pressure_file_path, e);
                        continue;
                    }

                    let fd = file.as_raw_fd();
                    let token = Token(next_token.0);
                    next_token.0 += 1;

                    poll.registry()
                        .register(&mut SourceFd(&fd), token, Interest::PRIORITY)
                        .unwrap();
                    token_map.insert(token, pid);
                    files.insert(pid, file);
                }
            }

            while running.load(Ordering::SeqCst) {
                trace!("Polling for PSI events");
                match poll.poll(&mut events, None) {
                    Ok(_) => (),
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                        debug!("Poll interrupted, continuing");
                        continue;
                    }
                    Err(e) => {
                        error!("Poll failed: {}", e);
                        break;
                    }
                }

                for event in events.iter() {
                    match event.token() {
                        WAKER_TOKEN => {
                            trace!("Received wake event");
                            if !running.load(Ordering::SeqCst) {
                                debug!("PSI monitoring stopping");
                                return;
                            }

                            let mut terminated_pids_lock = terminated_pids.lock().unwrap();
                            if !terminated_pids_lock.is_empty() {
                                debug!("Processing {} terminated PIDs", terminated_pids_lock.len());
                                for &pid in terminated_pids_lock.iter() {
                                    trace!("Removing watch for terminated PID: {}", pid);
                                    watches.lock().unwrap().remove(&pid);
                                    let token_to_remove = token_map.iter().find_map(|(k, &v)| {
                                        if v == pid {
                                            Some(k.clone())
                                        } else {
                                            None
                                        }
                                    });
                                    if let Some(token) = token_to_remove {
                                        token_map.remove(&token);
                                    }
                                    files.remove(&pid);
                                }
                            }
                            terminated_pids_lock.clear();
                            drop(terminated_pids_lock);

                            let mut new_pids_lock = new_pids.lock().unwrap();
                            if !new_pids_lock.is_empty() {
                                debug!("Processing {} new PIDs", new_pids_lock.len());
                                let watches_lock = watches.lock().unwrap();

                                for &pid in new_pids_lock.iter() {
                                    trace!("Setting up watch for new PID: {}", pid);
                                    if let Some(watch) = watches_lock.get(&pid) {
                                        let pressure_file_name = match watch.pressure_type {
                                            PressureType::Memory => "memory.pressure",
                                            PressureType::Cpu => "cpu.pressure",
                                            PressureType::Io => "io.pressure",
                                        };
                                        let pressure_file_path =
                                            format!("{}/{}", watch.cgroup_path, pressure_file_name);
                                        let mut file = match OpenOptions::new()
                                            .read(true)
                                            .write(true)
                                            .open(&pressure_file_path)
                                        {
                                            Ok(f) => f,
                                            Err(_e) => {
                                                continue;
                                            }
                                        };

                                        let trig = format!("some {} {}", interval_us, threshold_us);
                                        if let Err(e) = file.write_all(trig.as_bytes()) {
                                            error!(
                                                "Failed to write to {}: {}",
                                                pressure_file_path, e
                                            );
                                            continue;
                                        }

                                        let fd = file.as_raw_fd();
                                        let token = Token(next_token.0);
                                        next_token.0 += 1;

                                        poll.registry()
                                            .register(&mut SourceFd(&fd), token, Interest::PRIORITY)
                                            .unwrap();
                                        token_map.insert(token, pid);
                                        files.insert(pid, file);
                                    }
                                }
                            }
                            new_pids_lock.clear();
                            drop(new_pids_lock);
                        }
                        token => {
                            trace!("Received PSI event for token: {:?}", token);
                            if let Some(&pid) = token_map.get(&token) {
                                trace!("PSI event for PID: {}", pid);
                                if files.contains_key(&pid) {
                                    let mut content = String::new();
                                    let watch_guard = watches.lock().unwrap();
                                    let watch = watch_guard.get(&pid).unwrap();
                                    let pressure_file_name = match watch.pressure_type {
                                        PressureType::Memory => "memory.pressure",
                                        PressureType::Cpu => "cpu.pressure",
                                        PressureType::Io => "io.pressure",
                                    };
                                    let pressure_file_path =
                                        format!("{}/{}", watch.cgroup_path, pressure_file_name);
                                    if let Ok(mut f) = File::open(&pressure_file_path) {
                                        if f.read_to_string(&mut content).is_ok() {
                                            trace!(
                                                "Read PSI content for PID {}: {} bytes",
                                                pid,
                                                content.len()
                                            );
                                            let event = PressureEvent {
                                                pid,
                                                pressure_type: watch.pressure_type.clone(),
                                                pressure_data: content.trim_end().to_string(),
                                            };
                                            if let Err(e) = event_tx.send(event) {
                                                error!("Failed to broadcast PSI event: {}", e);
                                            }
                                            let cb = callback.lock().unwrap();
                                            if let Some(ref callback_fn) = *cb {
                                                info!(
                                                    "PSI event for process {}: 
{}",
                                                    pid,
                                                    content.trim_end()
                                                );
                                                callback_fn(pid, &content.trim_end());
                                            } else {
                                                info!(
                                                    "PSI event for process {}: 
{}",
                                                    pid,
                                                    content.trim_end()
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            debug!("PSI monitoring thread exiting");
        });

        let mut h = self.handle.lock().unwrap();
        *h = Some(handle);

        Ok(())
    }

    /// Stop the PSI monitoring
    #[instrument(skip(self))]
    pub fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Stopping PSI monitoring");
        self.running.store(false, Ordering::SeqCst);

        if let Some(waker) = self.waker.lock().unwrap().as_ref() {
            debug!("Waking PSI monitoring thread");
            waker.wake()?;
        }

        debug!("Joining PSI monitoring thread");
        let mut h = self.handle.lock().unwrap();
        if let Some(handle) = h.take() {
            debug!("Waiting for thread to complete");
            let _ = handle.join();
            debug!("Thread completed");
        }

        info!("PSI monitoring stopped");
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
    use crate::psi::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_psi_watcher() {
        let handle = thread::spawn(|| {
            let watcher = PsiWatcher::new();

            // Set a callback
            watcher.set_callback(|pid, info| {
                info!("PSI callback triggered for PID {}: {}", pid, info);
            });

            // Add current process to watch
            let current_pid = std::process::id();
            watcher.add_pid(current_pid, crate::PressureType::Memory);

            // Start the watcher
            if let Err(e) = watcher.start() {
                info!("Failed to start PSI watcher: {}", e);
                return;
            }

            thread::sleep(Duration::from_secs(2));

            let _ = watcher.stop();

            info!("PSI watcher test completed");
        });

        let start = std::time::Instant::now();
        while !handle.is_finished() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("Test timed out");
            }
            thread::sleep(Duration::from_millis(100));
        }

        match handle.join() {
            Ok(_) => {}
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
            watcher.add_pid(pid, crate::PressureType::Memory);

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
            Ok(_) => {}
            Err(e) => std::panic::resume_unwind(e),
        }
    }
}
