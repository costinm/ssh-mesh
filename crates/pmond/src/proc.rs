use crate::psi::PsiWatcher;
use crate::{read_process_info_from_proc, ProcMemInfo, ProcessInfo};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, trace};
use users::get_current_uid;

// ============================================================================
// Error Types
// ============================================================================

/// Custom error type for pmond operations.
#[derive(Debug, thiserror::Error)]
pub enum PmondError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Process not found: PID {0}")]
    ProcessNotFound(u32),

    #[error("Cgroup error: {0}")]
    CgroupError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Already running")]
    AlreadyRunning,

    #[error("PSI watcher error: {0}")]
    PsiError(String),
}

impl From<Box<dyn std::error::Error>> for PmondError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        PmondError::PsiError(e.to_string())
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for process monitoring.
#[derive(Debug, Clone, Default)]
pub struct ProcCfg {
    pub refresh_interval: Option<std::time::Duration>,
}

// ============================================================================
// Process Monitor
// ============================================================================

/// Monitors process state.
pub struct ProcMon {
    pub running: Arc<AtomicBool>,
    pub handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,

    pub psi_watcher: Arc<PsiWatcher>,

    pub config: Arc<Mutex<ProcCfg>>,

    // snap1 is the last periodic snapshot - should be less than refresh_interval old.
    pub snap1: Arc<Mutex<HashMap<u32, ProcessInfo>>>,

    // snap2 is the previous snapshot - between refresh and 2xrefresh.
    pub snap2: Arc<Mutex<HashMap<u32, ProcessInfo>>>,

    // snap_user is a user generate snapshot, at an arbitrary point in time.
    pub snap_user: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
}

impl ProcMon {
    /// Create a new monitor.
    #[instrument]
    pub fn new() -> Result<Self, PmondError> {
        let psi_watcher = Arc::new(PsiWatcher::new());

        Ok(ProcMon {
            running: Arc::new(AtomicBool::new(false)),
            handles: Arc::new(Mutex::new(Vec::new())),
            psi_watcher,
            config: Arc::new(Mutex::new(ProcCfg::default())),
            snap1: Arc::new(Mutex::new(HashMap::new())),
            snap2: Arc::new(Mutex::new(HashMap::new())),
            snap_user: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Update the configuration.
    pub fn set_config(&self, config: ProcCfg) {
        let mut cfg = self.config.lock();
        *cfg = config;
    }

    /// Start the monitoring and periodic checker. Will also read
    /// the existing processes and optionally maintain PSI watches.
    ///
    /// This method is not required - can just call get_process and get_all_processes
    /// directly without background update and PSI watching.
    #[instrument(skip(self), fields(read_sync = _read_sync, watch_psi = watch_psi))]
    pub fn start(
        &self,
        _read_sync: bool,
        watch_psi: bool,
        event_tx: Option<mpsc::Sender<crate::MonitoringEvent>>,
    ) -> Result<(), PmondError> {
        if self.running.load(Ordering::SeqCst) {
            return Err(PmondError::AlreadyRunning);
        }
        self.running.store(true, Ordering::SeqCst);

        let snapshot_handle = spawn_snapshot_checker(
            self.running.clone(),
            self.snap1.clone(),
            self.snap2.clone(),
            self.config.clone(),
            self.psi_watcher.clone(),
        );

        self.handles.lock().push(snapshot_handle);

        let initial_processes = read_existing_processes_impl();

        {
            let mut s1 = self.snap1.lock();
            let mut s2 = self.snap2.lock();

            *s1 = initial_processes.clone();
            *s2 = initial_processes.clone();
        }

        if watch_psi {
            debug!("Starting PSI watcher");
            self.psi_watcher.start(event_tx)?;
        }

        Ok(())
    }

    /// Stop monitoring.
    #[instrument(skip(self))]
    pub fn stop(&self) -> Result<(), PmondError> {
        debug!("Stopping monitoring");
        self.running.store(false, Ordering::SeqCst);

        debug!("Stopping PSI watcher");
        self.psi_watcher.stop()?;

        // Abort all spawned handles
        let handles = std::mem::take(&mut *self.handles.lock());
        for handle in handles {
            handle.abort();
        }

        info!("Monitoring stopped");
        Ok(())
    }

    /// Close the monitor and release resources.
    #[instrument(skip(self))]
    pub fn close(&self) -> Result<(), PmondError> {
        debug!("Closing ProcMon");
        self.stop()?;
        info!("ProcMon closed successfully");
        Ok(())
    }

    /// Retrieve current process by PID.
    #[instrument(skip(self), fields(pid = pid))]
    pub fn get_process(&self, pid: u32) -> Option<ProcessInfo> {
        trace!("Getting process by PID: {}", pid);

        match read_process_info_from_proc(pid) {
            Ok(process_info) => Some(process_info),
            Err(_) => None,
        }
    }

    /// Get all processes.
    /// mode 0: current life processes (real-time from /proc). If running, calculate deltas from snap1.
    /// mode 1: return snap1 (latest background snapshot).
    /// mode 2: return snap2 (previous background snapshot).
    #[instrument(skip(self))]
    pub fn get_all_processes(&self, mode: i32) -> HashMap<u32, ProcessInfo> {
        match mode {
            0 => {
                let mut current = read_existing_processes_impl();
                if self.running.load(Ordering::SeqCst) {
                    let s1 = self.snap1.lock();
                    calculate_memory_deltas(&mut current, &s1);
                }
                current
            }
            1 => self.snap1.lock().clone(),
            2 => self.snap2.lock().clone(),
            _ => {
                trace!("Invalid mode {}, defaulting to snap1", mode);
                self.snap1.lock().clone()
            }
        }
    }

    /// Read cgroup information by path.
    pub fn read_cgroup(&self, cgroup_path: &str) -> Option<ProcMemInfo> {
        crate::read_cgroup_info(cgroup_path).ok()
    }

    /// Get all cgroups used by known processes or present in /sys/fs/cgroup.
    pub fn get_all_cgroups(&self) -> HashMap<String, ProcMemInfo> {
        let mut cgroups = HashMap::new();

        // 1. Discovery via processes
        let processes = read_existing_processes_impl();
        for info in processes.values() {
            if let Some(ref cgroup_path) = info.cgroup_path {
                if !cgroups.contains_key(cgroup_path) {
                    if let Some(mem_info) = self.read_cgroup(cgroup_path) {
                        cgroups.insert(cgroup_path.clone(), mem_info);
                    }
                }
            }
        }

        // 2. Discovery via filesystem (scan /sys/fs/cgroup)
        self.scan_cgroups("/sys/fs/cgroup", &mut cgroups);

        cgroups
    }

    fn scan_cgroups(&self, dir: &str, cgroups: &mut HashMap<String, ProcMemInfo>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        let path = entry.path().to_string_lossy().into_owned();
                        if !cgroups.contains_key(&path) {
                            let procs_file = format!("{}/cgroup.procs", path);
                            if std::path::Path::new(&procs_file).exists() {
                                if let Ok(mem_info) = crate::read_cgroup_info(&path) {
                                    cgroups.insert(path.clone(), mem_info);
                                }
                            }
                        }
                        // Recurse into sub-cgroups
                        self.scan_cgroups(&path, cgroups);
                    }
                }
            }
        }
    }

    /// Adjust memory.high for a cgroup.
    /// percentage: 0.0 to 100.0, or negative for 'max'
    /// interval_secs: if > 0, reset to 'max' after this interval.
    pub fn adjust_cgroup_memory_high(
        &self,
        cgroup_path: String,
        percentage: f64,
        interval_secs: u64,
    ) -> Result<(), PmondError> {
        let current_path = format!("{}/memory.current", cgroup_path);
        let high_path = format!("{}/memory.high", cgroup_path);

        let current_str = fs::read_to_string(&current_path).map_err(|e| {
            let msg = format!("Failed to read {}: {}", current_path, e);
            error!("{}", msg);
            PmondError::CgroupError(msg)
        })?;

        let current: u64 = current_str.trim().parse().map_err(|e| {
            let msg = format!(
                "Failed to parse memory.current from {}: {}",
                current_path, e
            );
            error!("{}", msg);
            PmondError::ParseError(msg)
        })?;

        let target_str = if percentage < 0.0 {
            "max".to_string()
        } else {
            let target = (current as f64 * percentage / 100.0) as u64;
            target.to_string()
        };

        info!("Attempting to write {} to {}", target_str, high_path);
        fs::write(&high_path, &target_str).map_err(|e| {
            let msg = format!("Failed to write to {}: {}", high_path, e);
            error!("{}", msg);
            PmondError::CgroupError(msg)
        })?;

        info!(
            "Successfully set {} memory.high to {} (requested {}% of current {})",
            cgroup_path, target_str, percentage, current
        );

        if interval_secs > 0 && percentage >= 0.0 {
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
                info!("Interval expired. Resetting {} to max", high_path);
                if let Err(e) = tokio::fs::write(&high_path, "max").await {
                    error!(
                        "Failed to reset memory.high to max for {}: {}",
                        high_path, e
                    );
                } else {
                    info!(
                        "Successfully reset {} to max after {}s",
                        high_path, interval_secs
                    );
                }
            });
        }

        Ok(())
    }

    /// Get all processes in a specific cgroup.
    pub fn get_processes_in_cgroup(&self, cgroup_path: &str) -> Vec<crate::ProcessInfo> {
        let procs_path = format!("{}/cgroup.procs", cgroup_path);
        let mut result = Vec::new();

        if let Ok(content) = fs::read_to_string(&procs_path) {
            for line in content.lines() {
                if let Ok(pid) = line.trim().parse::<u32>() {
                    if let Ok(info) = crate::read_process_info_from_proc(pid) {
                        result.push(info);
                    }
                }
            }
        }
        result
    }

    /// Move a process to a new cgroup, under mesh.slice or custom systemd path.
    ///
    /// Moving processes will NOT move the memory stats and limits - they stay with the original
    /// group. This is useful for tracking new allocations after init and other special uses.
    /// SSH and long-running processes should be started with cgexec or similar wrappers - or moved
    /// immediately after startup if a wrapper (or using a library) is not possible.
    ///
    /// Will:
    ///  - find the process and it's current cgroup path.
    ///  - create a subdirectory on the cgroup path with the new cgroup_name if it doesn't exist.
    ///    This is under mesh.slice if systemd is not detected.
    ///  - move the process to the new cgroup.
    pub fn move_process_to_cgroup(
        &self,
        pid: u32,
        cgroup_name: Option<String>,
    ) -> Result<(), PmondError> {
        let process_info = self
            .get_process(pid)
            .ok_or(PmondError::ProcessNotFound(pid))?;

        // 1. Determine the base path for systemd delegation
        let uid = process_info.uid.unwrap_or(1000);
        let systemd_path = format!(
            "/sys/fs/cgroup/user.slice/user-{}.slice/user@{}.service",
            uid, uid
        );

        let base_path = if std::path::Path::new(&systemd_path).exists() {
            systemd_path
        } else {
            // Fallback: /sys/fs/cgroup/mesh.slice/user-{uid}.slice
            // We create this top-level to avoid systemd leaf node conflicts
            let mesh_top = "/sys/fs/cgroup/mesh.slice";
            let user_slice = format!("{}/user-{}.slice", mesh_top, uid);

            self.setup_cgroup_dir("/sys/fs/cgroup", "mesh.slice")?;
            self.setup_cgroup_dir(mesh_top, &format!("user-{}.slice", uid))?;

            user_slice
        };

        // 2. Enable controllers in the final base path before creating the scope
        self.enable_controllers(&base_path)?;

        // 3. Determine final cgroup name (must end in .scope for systemd delegation)
        let name = cgroup_name.unwrap_or_else(|| format!("{}-{}", process_info.comm, pid));
        let name = if name.contains('.') {
            name
        } else {
            format!("{}.scope", name)
        };

        let target_cgroup_path = format!("{}/{}", base_path, name);

        if !std::path::Path::new(&target_cgroup_path).exists() {
            fs::create_dir_all(&target_cgroup_path)?;
            info!("Created target cgroup: {}", target_cgroup_path);
        }

        // 4. Move the process
        let procs_path = format!("{}/cgroup.procs", target_cgroup_path);
        fs::write(&procs_path, pid.to_string())?;
        info!("Moved process {} to cgroup {}", pid, target_cgroup_path);

        // Refresh process info in cache after move
        let _ = self.get_process(pid);

        Ok(())
    }

    /// Ensure a cgroup directory exists and has controllers enabled in its parent.
    fn setup_cgroup_dir(&self, parent: &str, name: &str) -> Result<(), PmondError> {
        let path = format!("{}/{}", parent, name);
        if !std::path::Path::new(&path).exists() {
            fs::create_dir_all(&path)?;
            info!("Created cgroup directory: {}", path);
        }
        // Try to enable controllers in the parent for this child to use
        let _ = self.enable_controllers(parent);
        Ok(())
    }

    fn enable_controllers(&self, path: &str) -> Result<(), PmondError> {
        let controllers_path = format!("{}/cgroup.controllers", path);
        let subtree_control_path = format!("{}/cgroup.subtree_control", path);

        if let Ok(available) = fs::read_to_string(&controllers_path) {
            let mut to_enable = Vec::new();
            if available.contains("memory") {
                to_enable.push("+memory");
            }
            if available.contains("cpu") {
                to_enable.push("+cpu");
            }
            if available.contains("io") {
                to_enable.push("+io");
            }
            if !to_enable.is_empty() {
                let cmd = to_enable.join(" ");
                // Be careful: if there are processes in this node, writing to subtree_control will fail
                // with EBUSY in cgroupv2. We attempt it and log.
                if let Err(e) = fs::write(&subtree_control_path, &cmd) {
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        error!(
                            "Permission denied writing to {}. Run as root.",
                            subtree_control_path
                        );
                    } else {
                        debug!(
                            "Could not enable controllers in {}: {} (might have processes)",
                            subtree_control_path, e
                        );
                    }
                } else {
                    info!("Enabled controllers {} in {}", cmd, subtree_control_path);
                }
            }
        }
        Ok(())
    }

    /// Clear process memory references (PSS, etc)
    pub fn clear_refs(&self, pid: u32, value: &str) -> Result<(), PmondError> {
        crate::clear_process_refs(pid, value)?;
        // After clearing, we might want to refresh the stats immediately
        let _ = self.get_process(pid);
        Ok(())
    }

    /// Get all PSI watches and their current status.
    pub fn get_psi_watches(&self) -> std::collections::HashMap<String, crate::psi::PressureInfo> {
        self.psi_watcher.watches.lock().clone()
    }
}

// ============================================================================
// Standalone Helper Functions
// ============================================================================

/// Read existing processes from /proc. This is a standalone function that doesn't
/// require a full ProcMon instance.
fn read_existing_processes_impl() -> HashMap<u32, ProcessInfo> {
    let mut result = HashMap::new();

    // Check if we're running as root
    let current_uid = get_current_uid();
    let is_root = current_uid == 0;

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            {
                if let Ok(process_info) = crate::read_process_info_from_proc(pid) {
                    // Filter processes if not running as root
                    if !is_root && process_info.uid != Some(current_uid) {
                        continue;
                    }

                    trace!("Found process: {} (PID: {})", process_info.comm, pid);
                    result.insert(pid, process_info);
                }
            }
        }
    }
    result
}

/// Spawn the periodic snapshot checker task.
fn spawn_snapshot_checker(
    running: Arc<AtomicBool>,
    snap1: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    snap2: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    config: Arc<Mutex<ProcCfg>>,
    psi_watcher: Arc<PsiWatcher>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        run_snapshot_loop(running, snap1, snap2, config, psi_watcher);
    })
}

/// Main loop for periodic snapshot checking.
/// Main loop for periodic snapshot checking.
fn run_snapshot_loop(
    running: Arc<AtomicBool>,
    snap1: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    snap2: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    config: Arc<Mutex<ProcCfg>>,
    psi_watcher: Arc<PsiWatcher>,
) {
    while running.load(Ordering::SeqCst) {
        let interval = get_refresh_interval(&config);
        std::thread::sleep(interval);

        if !running.load(Ordering::SeqCst) {
            break;
        }

        // Take fresh snapshot
        let mut new_processes = read_existing_processes_impl();

        // --------------------------------------------------------------------
        // PSI Watcher Logic
        // --------------------------------------------------------------------

        // 1. Extract the set of cgroups referenced from each process in the new list
        let active_cgroups: HashSet<String> = new_processes
            .values()
            .filter_map(|p| p.cgroup_path.clone())
            .collect();

        // 2. Pass it to the psi_watcher - it should iterate over the cgroups it is watching
        // and remove any that is not present in the new list.
        psi_watcher.prune_cgroups(&active_cgroups);

        // 3. Go over snap2 - and find the set of cgroups referenced that is still present
        // in the set discovered at the first step.
        let stable_cgroups: HashSet<String> = {
            let s2 = snap2.lock();
            s2.values()
                .filter_map(|p| p.cgroup_path.clone())
                .filter(|path| active_cgroups.contains(path))
                .collect()
        };

        // 4. Pass it to psi watcher, and have it add any cgroup that is not already watched.
        // This will ensure psi is watching 'old' cgroups for processes that are still running.
        psi_watcher.watch_cgroups(&stable_cgroups);

        // --------------------------------------------------------------------
        // Delta Calculation and Snapshot Rotation
        // The intent is to know what changed in last 2 intervals.
        // --------------------------------------------------------------------
        {
            let mut s1 = snap1.lock();
            let mut s2 = snap2.lock();

            // 6. Compute the delta between snap1 and new_processes, saving the delta in new_processes
            // new_processes contains processes from T. snap1 contains processes from T-1.
            // We update new_processes to hold the diffs (T) - (T-1).
            calculate_memory_deltas(&mut new_processes, &s1);

            // 7. Finally set snap2 with snap1 and snap1 with new_processes
            // snap2 becomes the previous snap1 (T-1)
            *s2 = s1.clone();
            // snap1 becomes the new processes (T)
            *s1 = new_processes;
        }
    }
}

/// Get refresh interval from config, defaulting to 20 seconds.
fn get_refresh_interval(config: &Mutex<ProcCfg>) -> std::time::Duration {
    config
        .lock()
        .refresh_interval
        .unwrap_or(std::time::Duration::from_secs(20))
}

/// Calculate memory deltas between current and previous snapshots.
/// The `current` map is modified in-place to store the deltas.
fn calculate_memory_deltas(
    current: &mut HashMap<u32, ProcessInfo>,
    previous: &HashMap<u32, ProcessInfo>,
) {
    for (pid, proc1) in current.iter_mut() {
        if let Some(proc2) = previous.get(pid) {
            if let (Some(m1), Some(m2)) = (&mut proc1.mem_info, &proc2.mem_info) {
                m1.d_anon = m1.anon as i64 - m2.anon as i64;
                m1.d_file = m1.file as i64 - m2.file as i64;
                m1.d_kernel_stack = m1.kernel_stack as i64 - m2.kernel_stack as i64;
                m1.d_pagetables = m1.pagetables as i64 - m2.pagetables as i64;
                m1.d_shmem = m1.shmem as i64 - m2.shmem as i64;
                m1.d_pgfault = m1.pgfault as i64 - m2.pgfault as i64;
                m1.d_pgmajfault = m1.pgmajfault as i64 - m2.pgmajfault as i64;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_procmon_start_and_get_processes() {
        let proc_mon = ProcMon::new().expect("Failed to create ProcMon");
        proc_mon.set_config(ProcCfg {
            refresh_interval: Some(std::time::Duration::from_millis(100)),
        });
        proc_mon
            .start(true, false, None)
            .expect("Failed to start ProcMon");

        let processes = proc_mon.get_all_processes(1);
        assert!(
            !processes.is_empty(),
            "Processes list should not be empty after start()"
        );

        proc_mon.stop().expect("Failed to stop ProcMon");
    }

    #[test]
    fn test_pmond_error_display() {
        let io_err = PmondError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "test error",
        ));
        assert!(io_err.to_string().contains("I/O error"));

        let proc_err = PmondError::ProcessNotFound(1234);
        assert!(proc_err.to_string().contains("1234"));
    }
}
