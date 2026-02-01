/// Watching pressure (PSI) for a set of cgroups. The list is updated periodically
/// or by using cgroup-level APIs directly.
use crate::PressureType;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::io::AsRawFd;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::JoinHandle;
use std::time::{Instant, SystemTime};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, trace, warn};

const WAKER_TOKEN: Token = Token(1024);

/// Default PSI polling interval in microseconds
const DEFAULT_INTERVAL_US: u64 = 10000;
/// Default PSI threshold in microseconds (10 seconds)
const DEFAULT_THRESHOLD_US: u64 = 10000000;

/// Parsed PSI pressure data from /proc/pressure or cgroup memory.pressure files.
/// Format: "some avg10=X.XX avg60=X.XX avg300=X.XX total=N"
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PressureData {
    /// Average percentage of time stalled in the last 10 seconds
    pub avg10: f64,
    /// Average percentage of time stalled in the last 60 seconds
    pub avg60: f64,
    /// Average percentage of time stalled in the last 300 seconds
    pub avg300: f64,
    /// Total stall time in microseconds
    pub total: u64,
    /// Raw string if parsing failed
    pub raw: Option<String>,
}

impl PressureData {
    /// Parse PSI data from a string like "some avg10=0.00 avg60=0.00 avg300=0.00 total=0"
    pub fn parse(s: &str) -> Self {
        let mut data = PressureData::default();

        // Look for the "some" line (we're monitoring "some" pressure, not "full")
        for line in s.lines() {
            if line.starts_with("some") || !line.starts_with("full") {
                for part in line.split_whitespace() {
                    if let Some((key, val)) = part.split_once('=') {
                        match key {
                            "avg10" => data.avg10 = val.parse().unwrap_or(0.0),
                            "avg60" => data.avg60 = val.parse().unwrap_or(0.0),
                            "avg300" => data.avg300 = val.parse().unwrap_or(0.0),
                            "total" => data.total = val.parse().unwrap_or(0),
                            _ => {}
                        }
                    }
                }
                break;
            }
        }

        // Store raw if no meaningful data was parsed
        if data.total == 0 && data.avg10 == 0.0 && data.avg60 == 0.0 && data.avg300 == 0.0 {
            data.raw = Some(s.to_string());
        }

        data
    }
}

/// Tracks pressure information for a cgroup, including historical events.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PressureInfo {
    /// The cgroup path being watched
    pub cgroup_path: String,
    /// When this cgroup was first added to the watch list
    pub watch_started: SystemTime,
    /// The most recent pressure event data
    pub last_event: Option<PressureData>,
    /// Timestamp of the most recent event (monotonic)
    #[serde(skip)]
    pub last_event_time: Option<Instant>,
    /// The previous pressure event data (before last_event)
    pub previous_event: Option<PressureData>,
    /// Timestamp of the previous event (monotonic)
    #[serde(skip)]
    pub previous_event_time: Option<Instant>,
    /// Total number of pressure events received
    pub event_count: u64,
}

impl PressureInfo {
    /// Create a new PressureInfo for a cgroup
    pub fn new(cgroup_path: String) -> Self {
        Self {
            cgroup_path,
            watch_started: SystemTime::now(),
            last_event: None,
            last_event_time: None,
            previous_event: None,
            previous_event_time: None,
            event_count: 0,
        }
    }

    /// Record a new pressure event
    pub fn record_event(&mut self, data: PressureData) {
        // Shift last to previous
        self.previous_event = self.last_event.take();
        self.previous_event_time = self.last_event_time.take();
        // Set new last
        self.last_event = Some(data);
        self.last_event_time = Some(Instant::now());
        self.event_count += 1;
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PressureEvent {
    pub cgroup_path: String,
    pub pressure_type: PressureType,
    pub pressure_data: PressureData,
}

/// PsiWatcher is watching for memory pressure for a set of cgroups.
pub struct PsiWatcher {
    pub running: Arc<AtomicBool>,
    handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    waker: Arc<Mutex<Option<Waker>>>,

    // Cgroups being watched -> their pressure info
    pub watches: Arc<Mutex<HashMap<String, PressureInfo>>>,

    // Notification for the monitoring thread - to add and remove cgroups.
    new_cgroup_events: Arc<Mutex<Vec<String>>>,
    removed_cgroups: Arc<Mutex<Vec<String>>>,

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
        // Broadcast requires creating one receiver even if we don't use it
        let (event_tx, _) = broadcast::channel(100);
        let watcher = PsiWatcher {
            running: Arc::new(AtomicBool::new(false)),
            watches: Arc::new(Mutex::new(HashMap::new())),
            new_cgroup_events: Arc::new(Mutex::new(Vec::new())),
            removed_cgroups: Arc::new(Mutex::new(Vec::new())),
            handle: Arc::new(Mutex::new(None)),
            waker: Arc::new(Mutex::new(None)),
            event_tx,
            interval_us: DEFAULT_INTERVAL_US,
            threshold_us: DEFAULT_THRESHOLD_US,
        };
        watcher
    }

    /// Add a cgroup to the watch list.
    #[instrument(skip(self), fields(cgroup_path = cgroup_path))]
    pub fn add_cgroup(&self, cgroup_path: &str) {
        {
            let mut watches = self.watches.lock();
            if watches.contains_key(cgroup_path) {
                trace!("Cgroup {} already watched, skipping", cgroup_path);
                return;
            }
            watches.insert(
                cgroup_path.to_string(),
                PressureInfo::new(cgroup_path.to_string()),
            );
        }

        {
            let mut events = self.new_cgroup_events.lock();
            events.push(cgroup_path.to_string());
        }

        if let Some(waker) = self.waker.lock().as_ref() {
            if let Err(e) = waker.wake() {
                debug!(
                    "Failed to wake PSI watcher for cgroup {}: {}",
                    cgroup_path, e
                );
            } else {
                debug!("Wake signal sent for new cgroup {}", cgroup_path);
            }
        }
    }

    /// Remove a cgroup from the watch list.
    #[instrument(skip(self), fields(cgroup_path = cgroup_path))]
    pub fn remove_cgroup(&self, cgroup_path: &str) {
        {
            let mut watches = self.watches.lock();
            if watches.remove(cgroup_path).is_none() {
                return;
            }
        }

        let mut removed = self.removed_cgroups.lock();
        removed.push(cgroup_path.to_string());
        if let Some(waker) = self.waker.lock().as_ref() {
            if let Err(e) = waker.wake() {
                error!(
                    "Failed to wake PSI watcher for cgroup {}: {}",
                    cgroup_path, e
                );
            }
        }
        debug!("Cgroup {} removal signal queued", cgroup_path);
    }

    /// Prune cgroups that are no longer active.
    ///
    /// This will remove watches for any cgroup not in the `active_cgroups` set.
    #[instrument(skip(self, active_cgroups))]
    pub fn prune_cgroups(&self, active_cgroups: &HashSet<String>) {
        let cgroups_to_remove: Vec<String> = {
            let watches = self.watches.lock();
            watches
                .keys()
                .filter(|cgroup| !active_cgroups.contains(*cgroup))
                .cloned()
                .collect()
        };

        for cgroup in cgroups_to_remove {
            self.remove_cgroup(&cgroup);
        }
    }

    /// Ensure that the specified cgroups are being watched.
    ///
    /// Adds any cgroup in `target_cgroups` that is not currently watched.
    #[instrument(skip(self, target_cgroups))]
    pub fn watch_cgroups(&self, target_cgroups: &HashSet<String>) {
        // Identify which cgroups are already watched
        let watched_cgroups: std::collections::HashSet<String> =
            self.watches.lock().keys().cloned().collect();

        // Identify which cgroups need to be added
        let missing_cgroups: Vec<_> = target_cgroups
            .difference(&watched_cgroups)
            .cloned()
            .collect();

        for cgroup in missing_cgroups {
            self.add_cgroup(&cgroup);
        }
    }

    /// Start the PSI monitoring thread
    #[instrument(skip(self))]
    pub fn start(
        &self,
        monitoring_tx: Option<mpsc::Sender<crate::MonitoringEvent>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        let watches = self.watches.clone();
        let new_cgroup_events = self.new_cgroup_events.clone();
        let removed_cgroups = self.removed_cgroups.clone();
        let waker = self.waker.clone();
        let event_tx = self.event_tx.clone();
        let internal_monitoring_tx = monitoring_tx.clone();
        let interval_us = self.interval_us;
        let threshold_us = self.threshold_us;

        let handle = std::thread::spawn(move || {
            let mut poll = match Poll::new() {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to create mio Poll: {}", e);
                    return;
                }
            };
            let mut events = Events::with_capacity(2048);

            // Internal state - maps for tracking cgroup watches
            let mut token_to_cgroup: HashMap<Token, String> = HashMap::new();
            let mut cgroup_to_token: HashMap<String, Token> = HashMap::new();
            let mut cgroup_to_file: HashMap<String, File> = HashMap::new();
            let mut next_token = Token(0);
            let is_root = unsafe { libc::getuid() } == 0;

            let new_waker = match Waker::new(poll.registry(), WAKER_TOKEN) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to create Waker: {}", e);
                    return;
                }
            };
            *waker.lock() = Some(new_waker);

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
                        let is_root = unsafe { libc::getuid() } == 0;
                        if is_root {
                            debug!("Failed to open {}: {}", pressure_file_path, e);
                        } else {
                            trace!("Failed to open {}: {}", pressure_file_path, e);
                        }
                        return false;
                    }
                };

                let trig = format!("some {} {}", interval_us, threshold_us);
                if let Err(e) = file.write_all(trig.as_bytes()) {
                    let is_root = unsafe { libc::getuid() } == 0;
                    if is_root {
                        debug!("Failed to write trigger to {}: {}", pressure_file_path, e);
                    } else {
                        trace!("Failed to write trigger to {}: {}", pressure_file_path, e);
                    }
                    return false;
                }

                let fd = file.as_raw_fd();
                let token = Token(next_token.0);
                next_token.0 += 1;

                if let Err(e) =
                    poll.registry()
                        .register(&mut SourceFd(&fd), token, Interest::PRIORITY)
                {
                    let is_root = unsafe { libc::getuid() } == 0;
                    if is_root {
                        debug!("Failed to register {} with mio: {}", pressure_file_path, e);
                    } else {
                        trace!("Failed to register {} with mio: {}", pressure_file_path, e);
                    }
                    return false;
                }

                token_to_cgroup.insert(token, cgroup_path.to_string());
                cgroup_to_token.insert(cgroup_path.to_string(), token);
                cgroup_to_file.insert(cgroup_path.to_string(), file);
                debug!("Started watching cgroup: {}", cgroup_path);
                true
            }

            /// Helper to cleanup a cgroup watch
            fn cleanup_cgroup_watch(
                cgroup_path: &str,
                poll: &Poll,
                token_to_cgroup: &mut HashMap<Token, String>,
                cgroup_to_token: &mut HashMap<String, Token>,
                cgroup_to_file: &mut HashMap<String, File>,
            ) {
                if let Some(file) = cgroup_to_file.remove(cgroup_path) {
                    let fd = file.as_raw_fd();
                    if let Some(t) = cgroup_to_token.remove(cgroup_path) {
                        let _ = poll.registry().deregister(&mut SourceFd(&fd));
                        token_to_cgroup.remove(&t);
                    }
                }
                debug!("Cleaned up watch for cgroup: {}", cgroup_path);
            }

            {
                let watches_snapshot = watches.lock();
                for cgroup_path in watches_snapshot.keys() {
                    setup_cgroup_watch(
                        cgroup_path,
                        interval_us,
                        threshold_us,
                        &poll,
                        &mut next_token,
                        &mut token_to_cgroup,
                        &mut cgroup_to_token,
                        &mut cgroup_to_file,
                    );
                }
            }

            // Register system-wide memory pressure watch
            let system_pressure_path = "/proc/pressure/memory";
            if is_root && std::path::Path::new(system_pressure_path).exists() {
                match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(system_pressure_path)
                {
                    Ok(mut file) => {
                        let trig = format!("some {} {}", interval_us, threshold_us);
                        if let Err(e) = file.write_all(trig.as_bytes()) {
                            error!("Failed to write trigger to {}: {}", system_pressure_path, e);
                        } else {
                            let fd = file.as_raw_fd();
                            let token = Token(next_token.0);
                            next_token.0 += 1;
                            if let Err(e) = poll.registry().register(
                                &mut SourceFd(&fd),
                                token,
                                Interest::PRIORITY,
                            ) {
                                error!(
                                    "Failed to register {} with mio: {}",
                                    system_pressure_path, e
                                );
                            } else {
                                token_to_cgroup.insert(token, system_pressure_path.to_string());
                                cgroup_to_file.insert(system_pressure_path.to_string(), file);
                                debug!(
                                    "Started watching system pressure: {}",
                                    system_pressure_path
                                );
                            }
                        }
                    }
                    Err(e) => debug!("Failed to open system pressure file: {}", e),
                }
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

                            // Handle cgroup removals - drain vec first to minimize lock time
                            let cgroups_to_remove: Vec<String> = {
                                let mut lock = removed_cgroups.lock();
                                lock.drain(..).collect()
                            };

                            for cgroup_path in cgroups_to_remove {
                                cleanup_cgroup_watch(
                                    &cgroup_path,
                                    &poll,
                                    &mut token_to_cgroup,
                                    &mut cgroup_to_token,
                                    &mut cgroup_to_file,
                                );
                            }

                            // Handle new cgroups - drain vec first to minimize lock time
                            let new_cgroups: Vec<String> = {
                                let mut lock = new_cgroup_events.lock();
                                lock.drain(..).collect()
                            };

                            for cgroup_path in new_cgroups {
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
                                        let trimmed = content.trim_end();
                                        let pressure_data = PressureData::parse(trimmed);

                                        // Update the PressureInfo in watches
                                        if let Some(info) = watches.lock().get_mut(cgroup_path) {
                                            info.record_event(pressure_data.clone());
                                        }

                                        let event = PressureEvent {
                                            cgroup_path: cgroup_path.clone(),
                                            pressure_type: PressureType::Memory,
                                            pressure_data,
                                        };

                                        let _ = event_tx.send(event.clone());

                                        if let Some(ref tx) = internal_monitoring_tx {
                                            let _ = tx.blocking_send(
                                                crate::MonitoringEvent::Pressure(event),
                                            );
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

        let mut h = self.handle.lock();
        *h = Some(handle);

        Ok(())
    }

    /// Stop the PSI monitoring
    #[instrument(skip(self))]
    pub fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Stopping PSI monitoring");
        self.running.store(false, Ordering::SeqCst);

        if let Some(waker) = self.waker.lock().as_ref() {
            debug!("Waking PSI monitoring thread");
            waker.wake()?;
        }

        debug!("Joining PSI monitoring thread");
        let mut h = self.handle.lock();
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
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_psi_watcher() {
        let handle = thread::spawn(|| {
            let watcher = PsiWatcher::new();

            // Get current process cgroup and add it
            if let Some(cgroup_path) = crate::read_cgroup_path(std::process::id()) {
                watcher.add_cgroup(&cgroup_path);
            }

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

            // Use a test cgroup path (may not exist, but tests the API)
            let test_cgroup = "/sys/fs/cgroup/user.slice";

            if std::path::Path::new(test_cgroup).exists() {
                watcher.add_cgroup(test_cgroup);

                // Check that the cgroup is in watches
                {
                    let watches = watcher.watches.lock();
                    assert!(watches.contains_key(test_cgroup));
                }

                watcher.remove_cgroup(test_cgroup);

                // Allow some time for the watcher to process the removal
                std::thread::sleep(std::time::Duration::from_millis(100));

                // Check that the cgroup is no longer in watches
                {
                    let watches = watcher.watches.lock();
                    assert!(!watches.contains_key(test_cgroup));
                }
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
