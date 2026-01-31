/// Watching pressure (PSI) for a set of processes. The list is updated periodically
/// or by using netlink or manually.
use crate::{create_process_info, PressureType};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::io::AsRawFd;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, trace, warn};

const WAKER_TOKEN: Token = Token(1024);

/// Default PSI polling interval in microseconds
const DEFAULT_INTERVAL_US: u64 = 10000;
/// Default PSI threshold in microseconds (10 seconds)
const DEFAULT_THRESHOLD_US: u64 = 10000000;

#[derive(Debug, Clone, serde::Serialize)]
pub struct PressureEvent {
    pub pid: u32,
    pub pressure_type: PressureType,
    pub pressure_data: String,
}

pub struct PsiWatcher {
    pub running: Arc<AtomicBool>,
    // PID -> Cgroup Path
    pub watches: Arc<Mutex<HashMap<u32, String>>>,
    pub processes: Arc<Mutex<HashMap<u32, crate::ProcessInfo>>>,
    // Notification for the monitoring thread
    new_pid_events: Arc<Mutex<Vec<(u32, String)>>>,
    terminated_pids: Arc<Mutex<Vec<u32>>>,
    handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    callback: Arc<Mutex<Option<Box<dyn Fn(u32, &str) + Send + Sync>>>>,
    pub proc_callback: Arc<Mutex<Option<Box<dyn Fn(crate::ProcessInfo) + Send + Sync>>>>,
    waker: Arc<Mutex<Option<Waker>>>,
    pub event_tx: broadcast::Sender<PressureEvent>,
    pub interval_us: u64,
    pub threshold_us: u64,
}

impl Default for PsiWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PsiWatcher {
    /// Create a new PsiWatcher
    #[instrument]
    pub fn new() -> Self {
        debug!("Creating new PsiWatcher");
        // Broadcast requires creating one receiver even if we don't use it
        let (event_tx, _) = broadcast::channel(100);
        let watcher = PsiWatcher {
            running: Arc::new(AtomicBool::new(false)),
            watches: Arc::new(Mutex::new(HashMap::new())),
            processes: Arc::new(Mutex::new(HashMap::new())),
            new_pid_events: Arc::new(Mutex::new(Vec::new())),
            terminated_pids: Arc::new(Mutex::new(Vec::new())),
            handle: Arc::new(Mutex::new(None)),
            callback: Arc::new(Mutex::new(None)),
            proc_callback: Arc::new(Mutex::new(None)),
            waker: Arc::new(Mutex::new(None)),
            event_tx,
            interval_us: DEFAULT_INTERVAL_US,
            threshold_us: DEFAULT_THRESHOLD_US,
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

    /// Add a process to watch by PID (currently only Memory pressure is supported)
    #[instrument(skip(self), fields(pid = pid))]
    pub fn add_pid(&self, pid: u32) {
        debug!("Adding process {} to PSI watcher", pid);
        match create_process_info(pid) {
            Ok(process_info) => {
                if let Some(cgroup_path) = process_info.cgroup_path {
                    trace!("Found cgroup path for PID {}: {}", pid, cgroup_path);
                    {
                        let mut watches = self.watches.lock().unwrap();
                        watches.insert(pid, cgroup_path.clone());
                    }

                    {
                        let mut events = self.new_pid_events.lock().unwrap();
                        events.push((pid, cgroup_path));
                    }

                    if let Some(waker) = self.waker.lock().unwrap().as_ref() {
                        if let Err(e) = waker.wake() {
                            debug!("Failed to wake PSI watcher for PID {}: {}", pid, e);
                        } else {
                            debug!("Wake signal sent for new PID {}", pid);
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

    /// Handle a fork event
    pub fn handle_fork(&self, parent_tgid: u32, child_pid: u32, child_tgid: u32) {
        if let Ok(process_info) = crate::read_process_info_from_proc(child_tgid) {
            if parent_tgid == child_tgid {
                trace!(
                    "thread: parent pid={} -> child pid={} {} {}",
                    parent_tgid,
                    child_pid,
                    child_tgid,
                    process_info.comm
                );
            } else {
                trace!(
                    "fork: parent pid={} -> child pid={} {} tname/cmd ({}) {:?}",
                    parent_tgid,
                    child_pid,
                    child_tgid,
                    process_info.comm,
                    process_info.cmdline
                );

                {
                    let mut proc_map = self.processes.lock().unwrap();
                    proc_map.insert(process_info.pid, process_info.clone());
                }

                self.add_pid(process_info.pid);

                if let Some(cb) = self.proc_callback.lock().unwrap().as_ref() {
                    cb(process_info);
                }
            }
        }
    }

    /// Handle an exec event
    pub fn handle_exec(&self, _process_pid: u32, process_tgid: u32) {
        if let Ok(process_info) = crate::read_process_info_from_proc(process_tgid) {
            {
                let mut proc_map = self.processes.lock().unwrap();
                proc_map.insert(process_info.pid, process_info.clone());
            }
        }
    }

    /// Handle an exit event
    pub fn handle_exit(&self, process_tgid: u32) {
        self.processes.lock().unwrap().remove(&process_tgid);
        self.remove_pid(process_tgid);
    }

    /// Handle a UID change event
    pub fn handle_uid(&self, _process_pid: u32, process_tgid: u32, ruid: u32, euid: u32) {
        let mut proc_map = self.processes.lock().unwrap();
        if let Some(info) = proc_map.get_mut(&process_tgid) {
            info.uid = Some(ruid);
            trace!(
                "uid change: pid={} ruid={} euid={}",
                process_tgid,
                ruid,
                euid
            );
            let info_clone = info.clone();
            drop(proc_map);
            if let Some(cb) = self.proc_callback.lock().unwrap().as_ref() {
                cb(info_clone);
            }
        }
    }

    /// Handle a COMM change event (process name change)
    pub fn handle_comm(&self, _process_pid: u32, process_tgid: u32, comm: String) {
        let mut proc_map = self.processes.lock().unwrap();
        if let Some(info) = proc_map.get_mut(&process_tgid) {
            info.comm = comm;
            let info_clone = info.clone();
            drop(proc_map);
            if let Some(cb) = self.proc_callback.lock().unwrap().as_ref() {
                cb(info_clone);
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
        trace!("Process {} removal signal queued", pid);
    }

    /// Start the PSI monitoring thread
    #[instrument(skip(self))]
    pub fn start(
        &self,
        monitoring_tx: Option<mpsc::Sender<crate::MonitoringEvent>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Starting PSI monitoring thread");
        if self.running.load(Ordering::SeqCst) {
            debug!("PSI monitoring already running");
            return Ok(());
        }

        self.running.store(true, Ordering::SeqCst);
        info!("PSI monitoring started");

        let running = self.running.clone();
        let watches = self.watches.clone();
        let new_pid_events = self.new_pid_events.clone();
        let terminated_pids = self.terminated_pids.clone();
        let callback = self.callback.clone();
        let waker = self.waker.clone();
        let event_tx = self.event_tx.clone();
        let internal_monitoring_tx = monitoring_tx.clone();
        let interval_us = self.interval_us;
        let threshold_us = self.threshold_us;

        let handle = std::thread::spawn(move || {
            debug!("PSI monitoring thread started");

            let mut poll = match Poll::new() {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to create mio Poll: {}", e);
                    return;
                }
            };
            let mut events = Events::with_capacity(1024);

            // Internal state
            let mut cgroup_to_pids: HashMap<String, std::collections::HashSet<u32>> =
                HashMap::new();
            let mut token_to_cgroup: HashMap<Token, String> = HashMap::new();
            let mut cgroup_to_token: HashMap<String, Token> = HashMap::new(); // Reverse map for O(1) cleanup
            let mut cgroup_to_file: HashMap<String, File> = HashMap::new();
            let mut next_token = Token(0);

            let new_waker = match Waker::new(poll.registry(), WAKER_TOKEN) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to create Waker: {}", e);
                    return;
                }
            };
            *waker.lock().unwrap() = Some(new_waker);

            /// Helper to open and register a cgroup for PSI monitoring
            fn setup_cgroup_watch(
                cgroup_path: &str,
                interval_us: u64,
                threshold_us: u64,
                poll: &Poll,
                next_token: &mut Token,
                token_to_cgroup: &mut HashMap<Token, String>,
                cgroup_to_token: &mut HashMap<String, Token>,
                cgroup_to_file: &mut HashMap<String, File>,
            ) -> bool {
                let pressure_file_path = format!("{}/memory.pressure", cgroup_path);
                let mut file = match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&pressure_file_path)
                {
                    Ok(f) => f,
                    Err(e) => {
                        error!("Failed to open {}: {}", pressure_file_path, e);
                        return false;
                    }
                };

                let trig = format!("some {} {}", interval_us, threshold_us);
                if let Err(e) = file.write_all(trig.as_bytes()) {
                    error!("Failed to write trigger to {}: {}", pressure_file_path, e);
                    return false;
                }

                let fd = file.as_raw_fd();
                let token = Token(next_token.0);
                next_token.0 += 1;

                if let Err(e) =
                    poll.registry()
                        .register(&mut SourceFd(&fd), token, Interest::PRIORITY)
                {
                    error!("Failed to register {} with mio: {}", pressure_file_path, e);
                    return false;
                }

                token_to_cgroup.insert(token, cgroup_path.to_string());
                cgroup_to_token.insert(cgroup_path.to_string(), token);
                cgroup_to_file.insert(cgroup_path.to_string(), file);
                debug!("Started watching cgroup: {}", cgroup_path);
                true
            }

            // Initial setup - populate internal state from existing watches
            {
                let watches_snapshot = watches.lock().unwrap();
                for (&pid, cgroup_path) in watches_snapshot.iter() {
                    cgroup_to_pids
                        .entry(cgroup_path.clone())
                        .or_insert_with(std::collections::HashSet::new)
                        .insert(pid);
                }
            }

            // Open files and register watches for existing cgroups
            for cgroup_path in cgroup_to_pids.keys().cloned().collect::<Vec<_>>() {
                setup_cgroup_watch(
                    &cgroup_path,
                    interval_us,
                    threshold_us,
                    &poll,
                    &mut next_token,
                    &mut token_to_cgroup,
                    &mut cgroup_to_token,
                    &mut cgroup_to_file,
                );
            }

            while running.load(Ordering::SeqCst) {
                trace!("Polling for PSI events");
                match poll.poll(&mut events, None) {
                    Ok(_) => (),
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        error!("Poll failed: {}", e);
                        break;
                    }
                }

                for event in events.iter() {
                    match event.token() {
                        WAKER_TOKEN => {
                            if !running.load(Ordering::SeqCst) {
                                debug!("PSI monitoring stopping");
                                return;
                            }

                            // Handle terminations - drain vec first to minimize lock time
                            let pids_to_remove: Vec<u32> = {
                                let mut lock = terminated_pids.lock().unwrap();
                                lock.drain(..).collect()
                            };

                            for pid in pids_to_remove {
                                let mut cgroup_to_cleanup = None;

                                // Find which cgroup this PID belonged to and remove it
                                if let Some(cgroup_path) = watches.lock().unwrap().remove(&pid) {
                                    if let Some(pids) = cgroup_to_pids.get_mut(&cgroup_path) {
                                        pids.remove(&pid);
                                        if pids.is_empty() {
                                            cgroup_to_cleanup = Some(cgroup_path);
                                        }
                                    }
                                }

                                if let Some(path) = cgroup_to_cleanup {
                                    debug!("Cleaning up watch for empty cgroup: {}", path);
                                    cgroup_to_pids.remove(&path);
                                    if let Some(file) = cgroup_to_file.remove(&path) {
                                        let fd = file.as_raw_fd();
                                        // Use reverse map for O(1) lookup
                                        if let Some(t) = cgroup_to_token.remove(&path) {
                                            let _ = poll.registry().deregister(&mut SourceFd(&fd));
                                            token_to_cgroup.remove(&t);
                                        }
                                    }
                                }
                            }

                            // Handle new PIDs - drain vec first to minimize lock time
                            let new_pids: Vec<(u32, String)> = {
                                let mut lock = new_pid_events.lock().unwrap();
                                lock.drain(..).collect()
                            };

                            for (pid, cgroup_path) in new_pids {
                                if !cgroup_to_file.contains_key(&cgroup_path) {
                                    setup_cgroup_watch(
                                        &cgroup_path,
                                        interval_us,
                                        threshold_us,
                                        &poll,
                                        &mut next_token,
                                        &mut token_to_cgroup,
                                        &mut cgroup_to_token,
                                        &mut cgroup_to_file,
                                    );
                                }
                                cgroup_to_pids.entry(cgroup_path).or_default().insert(pid);
                            }
                        }
                        token => {
                            if let Some(cgroup_path) = token_to_cgroup.get(&token) {
                                trace!("PSI event for cgroup: {}", cgroup_path);
                                let mut content = String::new();
                                // We need to read from the file to clear the event
                                if let Some(file) = cgroup_to_file.get_mut(cgroup_path) {
                                    // Seek to start to read again
                                    if let Err(e) = file.seek(std::io::SeekFrom::Start(0)) {
                                        warn!(
                                            "Failed to seek in pressure file for {}: {}",
                                            cgroup_path, e
                                        );
                                    }
                                    if file.read_to_string(&mut content).is_ok() {
                                        let trimmed = content.trim_end().to_string();

                                        // Broadcast for ALL associated PIDs
                                        if let Some(pids) = cgroup_to_pids.get(cgroup_path) {
                                            for &pid in pids.iter() {
                                                let event = PressureEvent {
                                                    pid,
                                                    pressure_type: PressureType::Memory,
                                                    pressure_data: trimmed.clone(),
                                                };

                                                let _ = event_tx.send(event.clone());

                                                if let Some(ref tx) = internal_monitoring_tx {
                                                    let _ = tx.blocking_send(
                                                        crate::MonitoringEvent::Pressure(event),
                                                    );
                                                }

                                                if let Some(ref callback_fn) =
                                                    *callback.lock().unwrap()
                                                {
                                                    callback_fn(pid, &trimmed);
                                                }
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
                println!("PSI callback triggered for PID {}: {}", pid, info);
            });

            // Add current process to watch
            let current_pid = std::process::id();
            watcher.add_pid(current_pid);

            // Start the watcher
            if let Err(e) = watcher.start(None) {
                println!("Failed to start PSI watcher: {}", e);
                return;
            }

            thread::sleep(Duration::from_secs(2));

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
            Ok(_) => {}
            Err(e) => std::panic::resume_unwind(e),
        }
    }

    #[test]
    fn test_psi_watcher_dynamic_add_remove() {
        let handle = thread::spawn(|| {
            let watcher = PsiWatcher::new();
            watcher.start(None).unwrap();

            let mut child = std::process::Command::new("sleep")
                .arg("1")
                .spawn()
                .unwrap();

            let pid = child.id();
            watcher.add_pid(pid);

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
