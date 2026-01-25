//! PMON (Process Monitor) module for monitoring system processes

pub mod handlers;


pub mod proc;
pub mod proc_netlink;
pub mod psi;

pub use handlers::handle_ps_request;
pub use proc::ProcMon;
pub use psi::{PressureEvent, PsiWatcher};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PressureType {
    Memory,
    Cpu,
    Io,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub cgroup_path: Option<String>,
    pub cmdline: Option<String>,
    pub mem_info: Option<ProcMemInfo>,
    pub uid: Option<u32>,
}

/// memory.stats
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
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

    // Faults and VM activity
    pub pgfault: u64,
    pub pgmajfault: u64,
    pub pgrefill: u64,
    pub pgactivate: u64,
    pub pgdeactivate: u64,
    pub pswpin: u64,
    pub pswpout: u64,
    pub pgsteal: u64,
    pub pgscan: u64,

    // Demotion stats
    pub pgdemote_kswapd: u64,
    pub pgdemote_direct: u64,
    pub pgdemote_khugepaged: u64,
    pub pgdemote_proactive: u64,

    // Active/Inactive
    pub active_anon: u64,
    pub active_file: u64,
    pub inactive_anon: u64,
    pub inactive_file: u64,

    // Workingset stats
    pub workingset_refault_anon: u64,
    pub workingset_refault_file: u64,
    pub workingset_activate_anon: u64,
    pub workingset_activate_file: u64,
    pub workingset_restore_anon: u64,
    pub workingset_restore_file: u64,
    pub workingset_nodereclaim: u64,

    // Cgroup memory limits and usage
    pub memory_current: Option<u64>,
    pub memory_high: Option<String>,
}

/// Read process information from /proc/[pid]/stat (static version for global access)
pub fn read_process_info_from_proc(pid: u32) -> Result<ProcessInfo, Box<dyn std::error::Error>> {
    read_process_info_impl(pid)
}

/// Shared implementation for reading current process information.
pub fn read_process_info_impl(pid: u32) -> Result<ProcessInfo, Box<dyn std::error::Error>> {
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content = std::fs::read_to_string(stat_path)?;

    // Parse the stat file: format is "pid (comm) state ppid ..."
    let mut parts = stat_content.split_whitespace();
    let _pid = parts.next(); // pid is already known
    let comm = parts.next().unwrap_or("(unknown)");

    // Remove parentheses from comm. 16 chars max, no spaces.
    let comm = comm
        .trim_start_matches('(')
        .trim_end_matches(')')
        .to_string();

    let _state = parts.next().unwrap_or("?");
    let ppid = parts.next().unwrap_or("0").parse::<u32>().unwrap_or(0);

    // Skip other fields
    Ok(ProcessInfo {
        pid,
        ppid,
        comm,
        cgroup_path: read_cgroup_path(pid),
        cmdline: read_cmdline(pid),
        mem_info: read_memory_info(pid),
        uid: read_process_uid(pid),
    })
}

/// Read cgroup path for a process
pub fn read_cgroup_path(pid: u32) -> Option<String> {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    if let Ok(content) = std::fs::read_to_string(&cgroup_path) {
        for line in content.lines() {
            if line.starts_with("0::") {
                let cgroup = &line[3..];
                if !cgroup.is_empty() && cgroup != "/" {
                    return Some(format!("/sys/fs/cgroup{}", cgroup));
                }
            }
        }
    }
    None
}

/// Read memory information for a process from /proc/[pid]/status
pub fn read_memory_info(pid: u32) -> Option<ProcMemInfo> {
    let status_path = format!("/proc/{}/status", pid);
    let content = std::fs::read_to_string(&status_path).ok()?;

    let mut mem_info = ProcMemInfo::default();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let value_kb: u64 = parts[1].parse().unwrap_or(0);

        match parts[0] {
            "RssAnon:" => mem_info.anon = value_kb * 1024,
            "RssFile:" => mem_info.file = value_kb * 1024,
            "RssShmem:" => mem_info.shmem = value_kb * 1024,
            _ => (),
        }
    }

    Some(mem_info)
}

/// Read cmdline for a process
pub fn read_cmdline(pid: u32) -> Option<String> {
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(content) = std::fs::read_to_string(&cmdline_path) {
        if !content.is_empty() {
            let cmdline = content.replace("\0", " ").trim_end().to_string();
            if !cmdline.is_empty() {
                return Some(cmdline);
            }
        }
    }
    None
}

/// Read UID for a process from /proc/[pid]/status
pub fn read_process_uid(pid: u32) -> Option<u32> {
    let status_path = format!("/proc/{}/status", pid);
    if let Ok(content) = std::fs::read_to_string(&status_path) {
        for line in content.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(uid) = parts[1].parse::<u32>() {
                        return Some(uid);
                    }
                }
            }
        }
    }
    None
}

/// Create ProcessInfo for a given PID, including cgroup information
pub fn create_process_info(pid: u32) -> Result<ProcessInfo, Box<dyn std::error::Error>> {
    read_process_info_impl(pid)
}

/// Parse memory statistics from a cgroup path
pub fn parse_memory_stats(cgroup_path: &str) -> Result<ProcMemInfo, Box<dyn std::error::Error>> {
    let memory_stat_path = format!("{}/memory.stat", cgroup_path);
    let content = std::fs::read_to_string(&memory_stat_path)?;

    let mut mem_info = ProcMemInfo::default();

    // Try reading memory.current
    if let Ok(curr) = std::fs::read_to_string(format!("{}/memory.current", cgroup_path)) {
        mem_info.memory_current = curr.trim().parse().ok();
    }

    // Try reading memory.high
    if let Ok(high) = std::fs::read_to_string(format!("{}/memory.high", cgroup_path)) {
        mem_info.memory_high = Some(high.trim().to_string());
    }

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

            "pgfault" => mem_info.pgfault = value,
            "pgmajfault" => mem_info.pgmajfault = value,
            "pgrefill" => mem_info.pgrefill = value,
            "pgactivate" => mem_info.pgactivate = value,
            "pgdeactivate" => mem_info.pgdeactivate = value,
            "pswpin" => mem_info.pswpin = value,
            "pswpout" => mem_info.pswpout = value,
            "pgsteal" => mem_info.pgsteal = value,
            "pgscan" => mem_info.pgscan = value,

            "pgdemote_kswapd" => mem_info.pgdemote_kswapd = value,
            "pgdemote_direct" => mem_info.pgdemote_direct = value,
            "pgdemote_khugepaged" => mem_info.pgdemote_khugepaged = value,
            "pgdemote_proactive" => mem_info.pgdemote_proactive = value,

            "active_anon" => mem_info.active_anon = value,
            "active_file" => mem_info.active_file = value,
            "inactive_anon" => mem_info.inactive_anon = value,
            "inactive_file" => mem_info.inactive_file = value,

            "workingset_refault_anon" => mem_info.workingset_refault_anon = value,
            "workingset_refault_file" => mem_info.workingset_refault_file = value,
            "workingset_activate_anon" => mem_info.workingset_activate_anon = value,
            "workingset_activate_file" => mem_info.workingset_activate_file = value,
            "workingset_restore_anon" => mem_info.workingset_restore_anon = value,
            "workingset_restore_file" => mem_info.workingset_restore_file = value,
            "workingset_nodereclaim" => mem_info.workingset_nodereclaim = value,
            _ => (),
        }
    }

    Ok(mem_info)
}
