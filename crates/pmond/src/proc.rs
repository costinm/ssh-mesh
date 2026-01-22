use crate::psi::PsiWatcher;
use crate::{read_process_info_from_proc, PressureType, ProcMemInfo, ProcessInfo};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tracing::{debug, info, instrument, trace};
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
    #[instrument(skip(self), fields(watch_psi = watch_psi))]
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

    /// Get all cgroups used by known processes.
    pub fn get_all_cgroups(&self) -> HashMap<String, ProcMemInfo> {
        let processes = self.read_existing_processes(false);
        let mut cgroups = HashMap::new();

        for info in processes.values() {
            if let Some(ref cgroup_path) = info.cgroup_path {
                if !cgroups.contains_key(cgroup_path) {
                    if let Some(mem_info) = self.read_cgroup(cgroup_path) {
                        cgroups.insert(cgroup_path.clone(), mem_info);
                    }
                }
            }
        }

        cgroups
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
