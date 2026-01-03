use std::os::unix::io::RawFd;
use libc::close;
use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}, Mutex};
use std::thread::JoinHandle;
use std::fs;
use super::psi::{PressureType, PsiWatcher};
use super::proc_netlink::{proc_nl_connect, proc_set_ev_listen, proc_handle_ev};

// TODO:
// - more tests


// The rustix crate also has code to read the proc dir - not using it
// since this crate is pretty specialized and needs to read the files
// anyways.


#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub cgroup_path: Option<String>,
    pub cmdline: Option<String>,
}

/// memory.stats
#[derive(Debug, Clone)]
pub struct ProcMemInfo {
    pub anon: u64,
    pub file: u64,
    pub kernel: u64,
    pub kernel_stack: u64,
    pub pagetables: u64,
    pub shmem: u64,
    pub file_mapped: u64,
    pub file_dirty: u64,
    pub file_writeback: u64,
    pub swapcached: u64,
}

/// Monitors process events via Netlink.
pub struct ProcMon {
    pub nl_sock: RawFd,
    pub running: Arc<AtomicBool>,
    pub handle: Mutex<Option<JoinHandle<()>>>,
    pub callback: Arc<Mutex<Option<Box<dyn Fn(ProcessInfo) + Send + Sync>>>>,
    pub processes: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    pub psi_watcher: Arc<PsiWatcher>,
}

impl ProcMon {
    /// Create a new monitor and connect to Netlink.
    pub fn new() -> Result<Self, nix::Error> {
        let nl_sock = proc_nl_connect()?;
        let psi_watcher = PsiWatcher::new();
        psi_watcher.start().unwrap();
        psi_watcher.set_callback(|pid, info| {
            println!("PSI event for pid {}: {}", pid, info);
        });
        Ok(ProcMon {
            nl_sock,
            running: Arc::new(AtomicBool::new(false)),
            handle: Mutex::new(None),
            callback: Arc::new(Mutex::new(None)),
            processes: Arc::new(Mutex::new(HashMap::new())),
            psi_watcher: Arc::new(psi_watcher),
        })
    }

    /// Enable or disable listening for netlink events, for dynamically
    /// updating the list of processes.
    pub fn listen(&self, enable: bool) -> Result<(), nix::Error> {
        proc_set_ev_listen(self.nl_sock, enable)
    }

    /// Set a callback to be invoked when a new process is observed
    /// when using the netlink monitoring.
    pub fn set_callback<F>(&self, cb: F)
    where
        F: Fn(ProcessInfo) + Send + Sync + 'static,
    {
        let mut opt = self.callback.lock().unwrap();
        *opt = Some(Box::new(cb));
    }

    /// Start the netlink monitoring thread. Will also read
    /// the existing processes.
    pub fn start(&self, _read_sync: bool, watch_psi: bool) -> Result<(), nix::Error> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.running.store(true, Ordering::SeqCst);
        let nl_sock = self.nl_sock;
        let running = self.running.clone();
        let callback = self.callback.clone();
        let processes = self.processes.clone();
        let psi_watcher = self.psi_watcher.clone();
        let handle = std::thread::spawn(move || {

            // Wrap the proc_handle_ev call in a panic handler
            let result = std::panic::catch_unwind(|| {
                proc_handle_ev(nl_sock, callback, running, processes, psi_watcher)
            });

            match result {
                Ok(Ok(_)) => {
                    // Normal exit
                    println!("proc_handle_ev thread exited normally");
                }
                Ok(Err(e)) => {
                    // Error from proc_handle_ev
                    eprintln!("proc_handle_ev thread error: {:?}", e);
                }
                Err(e) => {
                    // Panic in proc_handle_ev
                    eprintln!("proc_handle_ev thread panicked: {:?}", e);
                }
            }
        });
        let mut h = self.handle.lock().unwrap();
        *h = Some(handle);

        self.read_existing_processes(watch_psi);

        Ok(())
    }

    /// Stop netlink monitoring and join the thread.
    pub fn stop(&self) -> Result<(), nix::Error> {
        self.listen(false)?;
        self.running.store(false, Ordering::SeqCst);
        self.psi_watcher.stop().unwrap();
        if self.nl_sock != 0 {
            unsafe { close(self.nl_sock) };
        }
        // Join the netlink monitoring thread
        let mut h = self.handle.lock().unwrap();
        if let Some(handle) = h.take() {
            std::thread::spawn(move || {
                let _ = handle.join();
            });
        }

        Ok(())
    }

    /// Close the monitor and release resources.
    pub fn close(&self) -> Result<(), nix::Error> {
        self.stop()?;
        Ok(())
    }

    /// Retrieve a process by PID.
    pub fn get_process(&self, pid: u32) -> Option<ProcessInfo> {
        let procs = self.processes.lock().unwrap();
        procs.get(&pid).cloned()
    }

    /// Get all processes
    pub fn get_all_processes(&self) -> HashMap<u32, ProcessInfo> {
        let procs = self.processes.lock().unwrap();
        procs.clone()
    }

    /// Read existing processes from /proc and populate the processes map
    pub fn read_existing_processes(&self, watch_psi: bool) {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries {
                if let Ok(entry) = entry {
                    if let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                        if let Ok(process_info) = read_process_info_impl(pid) {
                            let mut processes = self.processes.lock().unwrap();
                            processes.insert(pid, process_info.clone());

                            // If watching PSI and process has a cgroup, start monitoring
                            if watch_psi {
                                self.psi_watcher.add_pid(pid, PressureType::Memory);
                                self.psi_watcher.add_pid(pid, PressureType::Cpu);
                                self.psi_watcher.add_pid(pid, PressureType::Io);
                            }
                        }
                    }
                }
            }
        }
    }

}

/// Read process information from /proc/[pid]/stat (static version for global access)
pub fn read_process_info_from_proc(pid: u32) -> Result<ProcessInfo, Box<dyn std::error::Error>> {
    read_process_info_impl(pid)
}

/// Shared implementation for reading current process information.
/// The result will replace the existing value from the map, if any.
///
///
fn read_process_info_impl(pid: u32) -> Result<ProcessInfo, Box<dyn std::error::Error>> {
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content = std::fs::read_to_string(stat_path)?;

    // Parse the stat file: format is "pid (comm) state ppid ..."
    let mut parts = stat_content.split_whitespace();
    let _pid = parts.next(); // pid is already known
    let comm = parts.next().unwrap_or("(unknown)");

    // Remove parentheses from comm. 16 chars max, no spaces.
    // Base filename of the executable - or kernel task.
    let comm = comm.trim_start_matches('(').trim_end_matches(')').to_string();

    let _state = parts.next().unwrap_or("?");

    let ppid = parts.next().unwrap_or("0").parse::<u32>().unwrap_or(0);

    let _pgrp = parts.next().unwrap_or("?");
    let _session = parts.next().unwrap_or("?");
    let _ttynr = parts.next().unwrap_or("?");
    let _tpgid = parts.next().unwrap_or("?");
    let _flags = parts.next().unwrap_or("?");
    let _minflt = parts.next().unwrap_or("0");
    let _cminflt = parts.next().unwrap_or("0");

    // major faults - 12
    let _mjflt = parts.next().unwrap_or("0");
    let _cmjflt = parts.next().unwrap_or("0");

    //  Amount of time that this process has been scheduled
    //  in user mode, measured in clock ticks (divide by
    //  sysconf(_SC_CLK_TCK)).  This includes guest time,
    //  guest_time (time spent running a virtual CPU, see
    //  below), so that applications that are not aware of
    //  the guest time field do not lose that time from
    //  their calculations.
    let _utime = parts.next().unwrap_or("0");

    //  Amount of time that this process has been scheduled
    //  in kernel mode, measured in clock ticks (divide by
    //  sysconf(_SC_CLK_TCK)).
    let _stime = parts.next().unwrap_or("0");

    //  Amount of time that this process's waited-for
    //  children have been scheduled in user mode, measured
    //  in clock ticks (divide by sysconf(_SC_CLK_TCK)).
    //  (See also times(2).)  This includes guest time,
    //  cguest_time (time spent running a virtual CPU, see
    //  below).
    let _cutime = parts.next().unwrap_or("0");

    //  Amount of time that this process's waited-for
    //  children have been scheduled in kernel mode,
    //  measured in clock ticks (divide by
    //  sysconf(_SC_CLK_TCK)).
    let _cstime = parts.next().unwrap_or("0");
    let _priority = parts.next().unwrap_or("0");
    let _nice = parts.next().unwrap_or("0");
    let _num_threads = parts.next().unwrap_or("0");
    let _ = parts.next().unwrap_or("0");
    let _start_time = parts.next().unwrap_or("0");
    let _vsize = parts.next().unwrap_or("0");
    // Resident Set Size: number of pages the process has
    //  in real memory.  This is just the pages which count
    //  toward text, data, or stack space.  This does not
    //  include pages which have not been demand-loaded in,
    //  or which are swapped out.  This value is inaccurate;
    //  see /proc/pid/statm below.
    let _rss = parts.next().unwrap_or("0");
    let _ = parts.next().unwrap_or("0");
    let _ = parts.next().unwrap_or("0");

    Ok(ProcessInfo {
        pid,
        ppid,
        comm,
        cgroup_path: read_cgroup_path(pid),
        cmdline: read_cmdline(pid),
    })
}

/// Read cgroup path for a process
fn read_cgroup_path(pid: u32) -> Option<String> {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    if let Ok(content) = std::fs::read_to_string(&cgroup_path) {
        // Look for cgroup v2 entries (lines starting with "0::")
        for line in content.lines() {
            if line.starts_with("0::") {
                let cgroup = &line[3..]; // Skip "0::"
                if !cgroup.is_empty() && cgroup != "/" {
                    return Some(format!("/sys/fs/cgroup{}", cgroup));
                }
            }
        }
    }
    None
}

/// Read cmdline for a process
fn read_cmdline(pid: u32) -> Option<String> {
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(content) = std::fs::read_to_string(&cmdline_path) {
        // cmdline is null-separated, convert to space-separated for display
        if !content.is_empty() {
            let cmdline = content.replace('\0', " ").trim_end().to_string();
            if !cmdline.is_empty() {
                return Some(cmdline);
            }
        }
    }
    None
}


/// Create ProcessInfo for a given PID, including cgroup information
pub fn create_process_info(pid: u32) -> Result<ProcessInfo, Box<dyn std::error::Error>> {
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content = std::fs::read_to_string(stat_path)?;

    // Parse the stat file: format is "pid (comm) state ppid ..."
    let mut parts = stat_content.split_whitespace();
    let _pid = parts.next(); // pid is already known
    let comm = parts.next().unwrap_or("(unknown)");

    // Remove parentheses from comm
    let comm = comm.trim_start_matches('(').trim_end_matches(')').to_string();
    let ppid = parts.next().unwrap_or("0").parse::<u32>().unwrap_or(0);

    Ok(ProcessInfo {
        pid,
        ppid,
        comm,
        cgroup_path: read_cgroup_path(pid),
        cmdline: read_cmdline(pid),
    })
}

/// Parse memory statistics from a cgroup path
pub fn parse_memory_stats(cgroup_path: &str) -> Result<ProcMemInfo, Box<dyn std::error::Error>> {
    let memory_stat_path = format!("{}/memory.stat", cgroup_path);
    let content = std::fs::read_to_string(&memory_stat_path)?;

    let mut mem_info = ProcMemInfo {
        anon: 0,
        file: 0,
        kernel: 0,
        kernel_stack: 0,
        pagetables: 0,
        shmem: 0,
        file_mapped: 0,
        file_dirty: 0,
        file_writeback: 0,
        swapcached: 0,
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let value: u64 = parts[1].parse().unwrap_or(0);
        match parts[0] {
            "anon" => mem_info.anon = value,
            "file" => mem_info.file = value,
            "kernel" => mem_info.kernel = value,
            "kernel_stack" => mem_info.kernel_stack = value,
            "pagetables" => mem_info.pagetables = value,
            "shmem" => mem_info.shmem = value,
            "file_mapped" => mem_info.file_mapped = value,
            "file_dirty" => mem_info.file_dirty = value,
            "file_writeback" => mem_info.file_writeback = value,
            "swapcached" => mem_info.swapcached = value,
            _ => (),
        }
    }

    Ok(mem_info)
}

// --------- Tests ---------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_process_info() {
        // Test reading init process (PID 1) which should always exist
        if let Ok(process_info) = read_process_info_impl(1) {
            assert_eq!(process_info.pid, 1, "Expected PID 1");
            assert!(process_info.comm.len() > 0, "Expected non-empty command name");
        } else {
            // If we can't read PID 1, it might be permission issues, but the function should work
            // Try with current process PID instead
            let current_pid = std::process::id();
            if let Ok(process_info) = read_process_info_impl(current_pid) {
                assert_eq!(process_info.pid, current_pid, "Expected current PID");
                assert!(process_info.comm.len() > 0, "Expected non-empty command name");
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn test_create_process_info() {
        let current_pid = std::process::id();
        if let Ok(process_info) = create_process_info(current_pid) {
            assert_eq!(process_info.pid, current_pid);
            assert!(process_info.comm.len() > 0);
            // We can't assert much about cgroup_path since it depends on the environment
            // but we can check that it's either Some(_) or None
            match process_info.cgroup_path {
                Some(ref path) => assert!(path.starts_with("/sys/fs/cgroup")),
                None => (), // This is also valid
            }
                } else {
                    panic!("Failed to create ProcessInfo for current process");
                }
            }
        }
