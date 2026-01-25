use crate::psi::PsiWatcher;
use crate::{read_process_info_from_proc, PressureType, ProcMemInfo, ProcessInfo};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tracing::{debug, error, info, instrument, trace};
use users::get_current_uid;

/// Monitors process state.
pub struct ProcMon {
    pub running: Arc<AtomicBool>,
    pub handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,

    pub callback: Arc<Mutex<Option<Box<dyn Fn(ProcessInfo) + Send + Sync>>>>,

    pub processes: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    pub psi_watcher: Arc<PsiWatcher>,
}

impl ProcMon {
    pub fn get_psi_watches(&self) -> HashMap<u32, (PressureType, String)> {
        let watches_lock = self.psi_watcher.watches.lock().unwrap();
        let mut result = HashMap::new();

        for (&pid, watch) in watches_lock.iter() {
            let pressure_file_name = match watch.pressure_type {
                PressureType::Memory => "memory.pressure",
                PressureType::Cpu => "cpu.pressure",
                PressureType::Io => "io.pressure",
            };
            let pressure_file_path = format!("{}/{}", watch.cgroup_path, pressure_file_name);
            let mut content = String::new();
            if let Ok(mut f) = fs::File::open(&pressure_file_path) {
                if f.read_to_string(&mut content).is_ok() {
                    result.insert(
                        pid,
                        (watch.pressure_type.clone(), content.trim_end().to_string()),
                    );
                }
            }
        }
        result
    }
    /// Create a new monitor.
    #[instrument]
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        debug!("Creating new ProcMon instance");

        let psi_watcher = PsiWatcher::new();

        psi_watcher.set_callback(|pid, info| {
            info!("PSI event for pid {}: {}", pid, info);
        });

        info!("ProcMon created successfully");
        Ok(ProcMon {
            running: Arc::new(AtomicBool::new(false)),
            handles: Arc::new(Mutex::new(Vec::new())),
            callback: Arc::new(Mutex::new(None)),
            processes: Arc::new(Mutex::new(HashMap::new())),
            psi_watcher: Arc::new(psi_watcher),
        })
    }

    /// Handle a fork event - this is called when a Proc Netlink watcher is started
    /// and generates an event for a process start. The process will be updated and
    /// watched for PSI.
    pub fn handle_fork(&self, parent_tgid: u32, child_pid: u32, child_tgid: u32) {
        if let Ok(process_info) = read_process_info_from_proc(child_tgid) {
            if parent_tgid == child_tgid {
                debug!(
                    "thread: parent pid={} -> child pid={} {} {}",
                    parent_tgid, child_pid, child_tgid, process_info.comm
                );
            } else {
                debug!(
                    "fork: parent pid={} -> child pid={} {} tname/cmd ({}) {:?}",
                    parent_tgid, child_pid, child_tgid, process_info.comm, process_info.cmdline
                );

                {
                    let mut proc_map = self.processes.lock().unwrap();
                    proc_map.insert(process_info.pid, process_info.clone());
                }

                self.psi_watcher
                    .add_pid(process_info.pid, PressureType::Memory);
                self.psi_watcher
                    .add_pid(process_info.pid, PressureType::Cpu);
                self.psi_watcher.add_pid(process_info.pid, PressureType::Io);

                if let Some(cb) = self.callback.lock().unwrap().as_ref() {
                    cb(process_info);
                }
            }
        }
    }

    /// Handle an exit event.
    pub fn handle_exit(&self, process_tgid: u32) {
        info!("exit: pid={}", process_tgid);
        self.processes.lock().unwrap().remove(&process_tgid);
        self.psi_watcher.remove_pid(process_tgid);
    }

    /// Set a callback to be invoked when a new process is observed.
    pub fn set_callback<F>(&self, cb: F)
    where
        F: Fn(ProcessInfo) + Send + Sync + 'static,
    {
        let mut opt = self.callback.lock().unwrap();
        *opt = Some(Box::new(cb));
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Starting monitoring");
        if self.running.load(Ordering::SeqCst) {
            debug!("Monitoring already running");
            return Ok(());
        }
        self.running.store(true, Ordering::SeqCst);
        info!("Monitoring started");

        let running_checker = self.running.clone();
        let processes_checker = self.processes.clone();
        let psi_watcher_checker = self.psi_watcher.clone();

        // Spawn Periodic Checker (blocking due to file IO)
        let checker_handle = tokio::task::spawn_blocking(move || {
            periodic_process_checker(running_checker, processes_checker, psi_watcher_checker);
        });

        let mut handles = self.handles.lock().unwrap();
        handles.push(checker_handle);

        debug!("Reading existing processes");
        let initial_processes = self.read_existing_processes(watch_psi);
        {
            let mut processes = self.processes.lock().unwrap();
            *processes = initial_processes;
        }

        Ok(())
    }

    /// Stop monitoring.
    #[instrument(skip(self))]
    pub fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Stopping monitoring");
        self.running.store(false, Ordering::SeqCst);
        debug!("Stopping PSI watcher");
        self.psi_watcher.stop().unwrap();

        info!("Monitoring stopped");
        Ok(())
    }

    /// Close the monitor and release resources.
    #[instrument(skip(self))]
    pub fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
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
            Ok(process_info) => {
                let mut procs = self.processes.lock().unwrap();
                procs.insert(pid, process_info.clone());
                Some(process_info)
            }
            Err(_) => {
                let mut procs = self.processes.lock().unwrap();
                if procs.remove(&pid).is_some() {
                    debug!("Process {} no longer exists, removed from cache", pid);
                    self.psi_watcher.remove_pid(pid);
                }
                None
            }
        }
    }

    /// Get all processes
    #[instrument(skip(self))]
    pub fn get_all_processes(&self) -> HashMap<u32, ProcessInfo> {
        trace!("Getting all processes");
        self.read_existing_processes(false)
    }

    /// Read existing processes from /proc and optionally add them to the PSI watcher.
    //   #[instrument(skip(self), fields(watch_psi = watch_psi))]
    pub fn read_existing_processes(&self, watch_psi: bool) -> HashMap<u32, ProcessInfo> {
        debug!("Reading existing processes from /proc");
        let mut result = HashMap::new();

        // Check if we're running as root
        let current_uid = get_current_uid();
        let is_root = current_uid == 0;

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries {
                if let Ok(entry) = entry {
                    if let Some(pid) = entry
                        .file_name()
                        .to_str()
                        .and_then(|s| s.parse::<u32>().ok())
                    {
                        if let Ok(process_info) = read_process_info_from_proc(pid) {
                            // Filter processes if not running as root
                            if !is_root && process_info.uid != Some(current_uid) {
                                continue;
                            }

                            trace!("Found process: {} (PID: {})", process_info.comm, pid);
                            result.insert(pid, process_info.clone());

                            // If watching PSI and process has a cgroup, start monitoring
                            if watch_psi {
                                trace!("Adding PID {} to PSI watcher", pid);
                                self.psi_watcher.add_pid(pid, PressureType::Memory);
                                self.psi_watcher.add_pid(pid, PressureType::Cpu);
                                self.psi_watcher.add_pid(pid, PressureType::Io);
                            }
                        }
                    }
                }
            }
        }
        info!("Read {} existing processes", result.len());
        result
    }

    /// Read cgroup information by path.
    pub fn read_cgroup(&self, cgroup_path: &str) -> Option<ProcMemInfo> {
        crate::parse_memory_stats(cgroup_path).ok()
    }

    /// Get all cgroups used by known processes or present in /sys/fs/cgroup.
    pub fn get_all_cgroups(&self) -> HashMap<String, ProcMemInfo> {
        let mut cgroups = HashMap::new();

        // 1. Discovery via processes
        let processes = self.read_existing_processes(false);
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
                                if let Ok(mem_info) = crate::parse_memory_stats(&path) {
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        let current_path = format!("{}/memory.current", cgroup_path);
        let high_path = format!("{}/memory.high", cgroup_path);

        let current_str = fs::read_to_string(&current_path)?;
        let current: u64 = current_str.trim().parse()?;

        let target_str = if percentage < 0.0 {
            "max".to_string()
        } else {
            let target = (current as f64 * percentage / 100.0) as u64;
            target.to_string()
        };

        info!("Attempting to write {} to {}", target_str, high_path);
        fs::write(&high_path, &target_str)?;
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        let process_info = self.get_process(pid).ok_or("Process not found")?;

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
    fn setup_cgroup_dir(&self, parent: &str, name: &str) -> std::io::Result<()> {
        let path = format!("{}/{}", parent, name);
        if !std::path::Path::new(&path).exists() {
            fs::create_dir_all(&path)?;
            info!("Created cgroup directory: {}", path);
        }
        // Try to enable controllers in the parent for this child to use
        let _ = self.enable_controllers(parent);
        Ok(())
    }

    fn enable_controllers(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
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
    pub fn clear_refs(&self, pid: u32, value: &str) -> std::io::Result<()> {
        crate::clear_process_refs(pid, value)?;
        // After clearing, we might want to refresh the stats immediately
        let _ = self.get_process(pid);
        Ok(())
    }
}

/// Periodically check processes every 10 seconds to verify they still exist
/// and get current memory usage
fn periodic_process_checker(
    running: Arc<AtomicBool>,
    processes: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    psi_watcher: Arc<PsiWatcher>,
) {
    while running.load(Ordering::SeqCst) {
        // Sleep for 10 seconds
        std::thread::sleep(std::time::Duration::from_secs(10));

        if !running.load(Ordering::SeqCst) {
            break;
        }

        // Get the current set of PIDs we know about
        let old_pids: Vec<u32> = {
            let proc_map = processes.lock().unwrap();
            proc_map.keys().cloned().collect()
        };

        // Check each process and discover new ones
        let mut current_processes = HashMap::new();

        // Check if we're running as root
        let current_uid = get_current_uid();
        let is_root = current_uid == 0;

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries {
                if let Ok(entry) = entry {
                    if let Some(pid) = entry
                        .file_name()
                        .to_str()
                        .and_then(|s| s.parse::<u32>().ok())
                    {
                        if let Ok(process_info) = read_process_info_from_proc(pid) {
                            // Filter processes if not running as root
                            if !is_root && process_info.uid != Some(current_uid) {
                                continue;
                            }
                            current_processes.insert(pid, process_info);
                        }
                    }
                }
            }
        }

        // Update the shared state
        let mut proc_map = processes.lock().unwrap();
        *proc_map = current_processes.clone();

        // Clean up PSI watcher for disappeared processes
        for pid in old_pids {
            if !current_processes.contains_key(&pid) {
                psi_watcher.remove_pid(pid);
            }
        }
    }
}
