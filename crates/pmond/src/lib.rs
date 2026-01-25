use serde::{Deserialize, Serialize};

pub mod handlers;
pub mod proc;
pub mod proc_netlink;
pub mod psi;

pub use proc::ProcMon;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum PressureType {
    Memory,
    Cpu,
    Io,
}

pub use read_process_info as read_process_info_from_proc;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub cgroup_path: Option<String>,
    pub cmdline: Option<String>,
    pub mem_info: Option<ProcMemInfo>,
    pub uid: Option<u32>,
}

/// Memory info for a process or cgroup. Each field should have a comment indicating
/// where it is derived from.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ProcMemInfo {
    // --- Common Fields (Both Process and Cgroup) ---
    /// Anonymous memory. Process: smaps_rollup (Anonymous), status (RssAnon), or statm. Cgroup: memory.stat (anon).
    pub anon: u64,
    /// File-backed memory. Process: Derived (rss - anon) or status (RssFile). Cgroup: memory.stat (file).
    pub file: u64,
    /// Kernel stack memory. Process: status (VmStk). Cgroup: memory.stat (kernel_stack).
    pub kernel_stack: u64,
    /// Page table entries. Process: status (VmPTE). Cgroup: memory.stat (pagetables).
    pub pagetables: u64,
    /// Shared memory. Process: status (RssShmem) or statm (shared). Cgroup: memory.stat (shmem).
    pub shmem: u64,
    /// Page faults. Process: stat (minflt + majflt). Cgroup: memory.stat (pgfault).
    pub pgfault: u64,
    /// Major page faults. Process: stat (majflt). Cgroup: memory.stat (pgmajfault).
    pub pgmajfault: u64,

    // --- Process Only Fields ---
    /// Proportional Set Size. Process: smaps_rollup (Pss). Cgroup: N/A.
    pub pss: u64,
    /// Total Resident Set Size. Process: smaps_rollup (Rss), status (VmRSS), or statm. Cgroup: N/A (see memory_current).
    pub rss: u64,
    /// Private clean pages. Process: smaps_rollup (Private_Clean). Cgroup: N/A.
    pub private_clean: u64,
    /// Private dirty pages. Process: smaps_rollup (Private_Dirty). Cgroup: N/A.
    pub private_dirty: u64,
    /// Shared clean pages. Process: smaps_rollup (Shared_Clean). Cgroup: N/A.
    pub shared_clean: u64,
    /// Shared dirty pages. Process: smaps_rollup (Shared_Dirty). Cgroup: N/A.
    pub shared_dirty: u64,
    /// Referenced memory. Process: smaps_rollup (Referenced). Cgroup: N/A.
    pub referenced: u64,
    /// Total swap usage. Process: smaps_rollup (Swap) or status (VmSwap). Cgroup: N/A.
    pub swap: u64,
    /// HugeTLB memory. Process: status (HugetlbPages). Cgroup: N/A.
    pub hugetlb: u64,

    // --- Cgroup Only Fields ---
    /// Kernel memory. Process: N/A. Cgroup: memory.stat (kernel).
    pub kernel: u64,
    /// Mapped file memory. Process: N/A (partial in smaps). Cgroup: memory.stat (file_mapped).
    pub file_mapped: u64,
    /// Dirty file cache. Process: N/A. Cgroup: memory.stat (file_dirty).
    pub file_dirty: u64,
    /// Writeback file cache. Process: N/A. Cgroup: memory.stat (file_writeback).
    pub file_writeback: u64,
    /// Memory that is swap-cached. Process: N/A. Cgroup: memory.stat (swapcached).
    pub swapcached: u64,
    /// Page refills. Cgroup: memory.stat (pgrefill).
    pub pgrefill: u64,
    /// Pages activated. Cgroup: memory.stat (pgactivate).
    pub pgactivate: u64,
    /// Pages deactivated. Cgroup: memory.stat (pgdeactivate).
    pub pgdeactivate: u64,
    /// Pages swapped in. Cgroup: memory.stat (pswpin).
    pub pswpin: u64,
    /// Pages swapped out. Cgroup: memory.stat (pswpout).
    pub pswpout: u64,
    /// Pages stolen. Cgroup: memory.stat (pgsteal).
    pub pgsteal: u64,
    /// Pages scanned. Cgroup: memory.stat (pgscan).
    pub pgscan: u64,
    /// Pages demoted by kswapd. Cgroup: memory.stat (pgdemote_kswapd).
    pub pgdemote_kswapd: u64,
    /// Pages demoted directly. Cgroup: memory.stat (pgdemote_direct).
    pub pgdemote_direct: u64,
    /// Pages demoted by khugepaged. Cgroup: memory.stat (pgdemote_khugepaged).
    pub pgdemote_khugepaged: u64,
    /// Pages demoted proactively. Cgroup: memory.stat (pgdemote_proactive).
    pub pgdemote_proactive: u64,
    /// Active anonymous memory. Cgroup: memory.stat (active_anon).
    pub active_anon: u64,
    /// Active file memory. Cgroup: memory.stat (active_file).
    pub active_file: u64,
    /// Inactive anonymous memory. Cgroup: memory.stat (inactive_anon).
    pub inactive_anon: u64,
    /// Inactive file memory. Cgroup: memory.stat (inactive_file).
    pub inactive_file: u64,
    /// Workingset refaults for anon. Cgroup: memory.stat (workingset_refault_anon).
    pub workingset_refault_anon: u64,
    /// Workingset refaults for file. Cgroup: memory.stat (workingset_refault_file).
    pub workingset_refault_file: u64,
    /// Workingset activations for anon. Cgroup: memory.stat (workingset_activate_anon).
    pub workingset_activate_anon: u64,
    /// Workingset activations for file. Cgroup: memory.stat (workingset_activate_file).
    pub workingset_activate_file: u64,
    /// Workingset restores for anon. Cgroup: memory.stat (workingset_restore_anon).
    pub workingset_restore_anon: u64,
    /// Workingset restores for file. Cgroup: memory.stat (workingset_restore_file).
    pub workingset_restore_file: u64,
    /// Workingset node reclaim. Cgroup: memory.stat (workingset_nodereclaim).
    pub workingset_nodereclaim: u64,
    /// Current cgroup memory current usage. Cgroup: memory.current.
    pub memory_current: Option<u64>,
    /// Cgroup memory high limit. Cgroup: memory.high.
    pub memory_high: Option<String>,
}

impl ProcMemInfo {
    /// Merge fields from another ProcMemInfo if they are zero or None in this one.
    pub fn merge(&mut self, other: &ProcMemInfo) {
        if self.pss == 0 {
            self.pss = other.pss;
        }
        if self.anon == 0 {
            self.anon = other.anon;
        }
        if self.file == 0 {
            self.file = other.file;
        }
        if self.kernel_stack == 0 {
            self.kernel_stack = other.kernel_stack;
        }
        if self.pagetables == 0 {
            self.pagetables = other.pagetables;
        }
        if self.shmem == 0 {
            self.shmem = other.shmem;
        }
        if self.pgfault == 0 {
            self.pgfault = other.pgfault;
        }
        if self.pgmajfault == 0 {
            self.pgmajfault = other.pgmajfault;
        }
        if self.rss == 0 {
            self.rss = other.rss;
        }
        if self.private_clean == 0 {
            self.private_clean = other.private_clean;
        }
        if self.private_dirty == 0 {
            self.private_dirty = other.private_dirty;
        }
        if self.shared_clean == 0 {
            self.shared_clean = other.shared_clean;
        }
        if self.shared_dirty == 0 {
            self.shared_dirty = other.shared_dirty;
        }
        if self.referenced == 0 {
            self.referenced = other.referenced;
        }
        if self.swap == 0 {
            self.swap = other.swap;
        }
        if self.hugetlb == 0 {
            self.hugetlb = other.hugetlb;
        }
        if self.kernel == 0 {
            self.kernel = other.kernel;
        }
        if self.file_mapped == 0 {
            self.file_mapped = other.file_mapped;
        }
        if self.file_dirty == 0 {
            self.file_dirty = other.file_dirty;
        }
        if self.file_writeback == 0 {
            self.file_writeback = other.file_writeback;
        }
        if self.swapcached == 0 {
            self.swapcached = other.swapcached;
        }
        if self.pgrefill == 0 {
            self.pgrefill = other.pgrefill;
        }
        if self.pgactivate == 0 {
            self.pgactivate = other.pgactivate;
        }
        if self.pgdeactivate == 0 {
            self.pgdeactivate = other.pgdeactivate;
        }
        if self.pswpin == 0 {
            self.pswpin = other.pswpin;
        }
        if self.pswpout == 0 {
            self.pswpout = other.pswpout;
        }
        if self.pgsteal == 0 {
            self.pgsteal = other.pgsteal;
        }
        if self.pgscan == 0 {
            self.pgscan = other.pgscan;
        }
        if self.pgdemote_kswapd == 0 {
            self.pgdemote_kswapd = other.pgdemote_kswapd;
        }
        if self.pgdemote_direct == 0 {
            self.pgdemote_direct = other.pgdemote_direct;
        }
        if self.pgdemote_khugepaged == 0 {
            self.pgdemote_khugepaged = other.pgdemote_khugepaged;
        }
        if self.pgdemote_proactive == 0 {
            self.pgdemote_proactive = other.pgdemote_proactive;
        }
        if self.active_anon == 0 {
            self.active_anon = other.active_anon;
        }
        if self.active_file == 0 {
            self.active_file = other.active_file;
        }
        if self.inactive_anon == 0 {
            self.inactive_anon = other.inactive_anon;
        }
        if self.inactive_file == 0 {
            self.inactive_file = other.inactive_file;
        }
        if self.workingset_refault_anon == 0 {
            self.workingset_refault_anon = other.workingset_refault_anon;
        }
        if self.workingset_refault_file == 0 {
            self.workingset_refault_file = other.workingset_refault_file;
        }
        if self.workingset_activate_anon == 0 {
            self.workingset_activate_anon = other.workingset_activate_anon;
        }
        if self.workingset_activate_file == 0 {
            self.workingset_activate_file = other.workingset_activate_file;
        }
        if self.workingset_restore_anon == 0 {
            self.workingset_restore_anon = other.workingset_restore_anon;
        }
        if self.workingset_restore_file == 0 {
            self.workingset_restore_file = other.workingset_restore_file;
        }
        if self.workingset_nodereclaim == 0 {
            self.workingset_nodereclaim = other.workingset_nodereclaim;
        }
        if self.memory_current.is_none() {
            self.memory_current = other.memory_current;
        }
        if self.memory_high.is_none() {
            self.memory_high = other.memory_high.clone();
        }
    }
}

/// Read process information from /proc/[pid]/stat (static version for global access)
pub fn read_process_info(pid: u32) -> Result<ProcessInfo, Box<dyn std::error::Error>> {
    read_process_info_impl(pid)
}

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

    let cgroup_path = read_cgroup_path(pid);
    let mem_info = read_memory_info(pid).unwrap_or_default();

    Ok(ProcessInfo {
        pid,
        ppid,
        comm,
        cgroup_path,
        cmdline: read_cmdline(pid),
        mem_info: Some(mem_info),
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
                if cgroup == "/" {
                    return Some("/sys/fs/cgroup".to_string());
                } else if !cgroup.is_empty() {
                    return Some(format!("/sys/fs/cgroup{}", cgroup));
                }
            }
        }
    }
    None
}

/// Read memory information for a process from /proc/[pid]/smaps_rollup, /proc/[pid]/status, /proc/[pid]/stat and /proc/[pid]/statm as fallback
pub fn read_memory_info(pid: u32) -> Option<ProcMemInfo> {
    let mut mem_info = ProcMemInfo::default();
    let mut found_any = false;

    // 0. Try /proc/[pid]/stat for faults
    let stat_path = format!("/proc/{}/stat", pid);
    if let Ok(content) = std::fs::read_to_string(&stat_path) {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 12 {
            // Field 10 is minflt, 12 is majflt (0-indexed: 9, 11)
            let min_faults: u64 = parts[9].parse().unwrap_or(0);
            let maj_faults: u64 = parts[11].parse().unwrap_or(0);
            mem_info.pgfault = min_faults + maj_faults;
            mem_info.pgmajfault = maj_faults;
            found_any = true;
        }
    }

    // 1. Try /proc/[pid]/smaps_rollup for accurate PSS and RSS breakdown
    let rollup_path = format!("/proc/{}/smaps_rollup", pid);
    if let Ok(content) = std::fs::read_to_string(&rollup_path) {
        let mut rollup_found = false;
        for line in content.lines() {
            if let Some(colon_idx) = line.find(':') {
                let key = line[..colon_idx].trim();
                let value_part = line[colon_idx + 1..].trim();
                let val_kb: u64 = value_part
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);

                match key {
                    "Rss" => {
                        mem_info.rss = val_kb * 1024;
                        rollup_found = true;
                    }
                    "Pss" => {
                        mem_info.pss = val_kb * 1024;
                        rollup_found = true;
                    }
                    "Anonymous" => {
                        mem_info.anon = val_kb * 1024;
                        rollup_found = true;
                    }
                    "Private_Clean" => mem_info.private_clean = val_kb * 1024,
                    "Private_Dirty" => mem_info.private_dirty = val_kb * 1024,
                    "Shared_Clean" => mem_info.shared_clean = val_kb * 1024,
                    "Shared_Dirty" => mem_info.shared_dirty = val_kb * 1024,
                    "Swap" => mem_info.swap = val_kb * 1024,
                    "Referenced" => {
                        mem_info.referenced = val_kb * 1024;
                        rollup_found = true;
                    }
                    _ => (),
                }
            }
        }
        if rollup_found {
            found_any = true;
            // Derive file-backed RSS if possible
            if mem_info.rss > mem_info.anon {
                mem_info.file = mem_info.rss - mem_info.anon;
            }
        }
    }

    // 2. Try /proc/[pid]/status for other fields (PTE, Stack, Shmem)
    let status_path = format!("/proc/{}/status", pid);
    if let Ok(content) = std::fs::read_to_string(&status_path) {
        for line in content.lines() {
            if let Some(colon_idx) = line.find(':') {
                let key = line[..colon_idx].trim();
                let value_part = line[colon_idx + 1..].trim();
                let val_kb: u64 = value_part
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);

                match key {
                    "RssAnon" if mem_info.anon == 0 => {
                        mem_info.anon = val_kb * 1024;
                        found_any = true;
                    }
                    "RssFile" if mem_info.file == 0 => {
                        mem_info.file = val_kb * 1024;
                        found_any = true;
                    }
                    "RssShmem" => {
                        mem_info.shmem = val_kb * 1024;
                        found_any = true;
                    }
                    "VmPTE" => {
                        mem_info.pagetables = val_kb * 1024;
                        found_any = true;
                    }
                    "VmStk" => {
                        mem_info.kernel_stack = val_kb * 1024;
                        found_any = true;
                    }
                    "VmSwap" if mem_info.swap == 0 => {
                        mem_info.swap = val_kb * 1024;
                        found_any = true;
                    }
                    "VmRSS" if mem_info.rss == 0 => {
                        mem_info.rss = val_kb * 1024;
                        found_any = true;
                    }
                    "HugetlbPages" => {
                        mem_info.hugetlb = val_kb * 1024;
                        found_any = true;
                    }
                    _ => (),
                }
            }
        }
    }

    // 3. Try /proc/[pid]/statm as a fallback for total RSS
    if !found_any || (mem_info.anon == 0 && mem_info.rss == 0) {
        let statm_path = format!("/proc/{}/statm", pid);
        if let Ok(content) = std::fs::read_to_string(&statm_path) {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() >= 3 {
                let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
                if page_size > 0 {
                    let resident_pages: u64 = parts[1].parse().unwrap_or(0);
                    let shared_pages: u64 = parts[2].parse().unwrap_or(0);

                    if mem_info.rss == 0 {
                        mem_info.rss = resident_pages * page_size;
                        found_any = true;
                    }
                    if mem_info.anon == 0 {
                        let total_rss = resident_pages * page_size;
                        let shared = shared_pages * page_size;
                        mem_info.shmem = shared;
                        mem_info.anon = if total_rss > shared {
                            total_rss - shared
                        } else {
                            total_rss
                        };
                        found_any = true;
                    }
                }
            }
        }
    }

    if found_any {
        // Check if process has a dedicated cgroup (-PID.scope)
        if let Some(cg_path) = read_cgroup_path(pid) {
            let expected_suffix = format!("-{}.scope", pid);
            if cg_path.ends_with(&expected_suffix) {
                if let Ok(cg_info) = parse_memory_stats(&cg_path) {
                    mem_info.merge(&cg_info);
                }
            }
        }
        Some(mem_info)
    } else {
        None
    }
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
    let mut mem_info = ProcMemInfo::default();

    if !std::path::Path::new(cgroup_path).is_dir() {
        return Err(format!("Not a cgroup directory: {}", cgroup_path).into());
    }

    if let Ok(curr) = std::fs::read_to_string(format!("{}/memory.current", cgroup_path)) {
        mem_info.memory_current = curr.trim().parse().ok();
    }

    if let Ok(high) = std::fs::read_to_string(format!("{}/memory.high", cgroup_path)) {
        mem_info.memory_high = Some(high.trim().to_string());
    }

    let memory_stat_path = format!("{}/memory.stat", cgroup_path);
    if let Ok(content) = std::fs::read_to_string(&memory_stat_path) {
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
    }
    Ok(mem_info)
}

/// Reset process references (PSS, soft-dirty, etc) via /proc/[pid]/clear_refs
/// Values:
/// 1: reset PSS, soft-dirty, etc
/// 2: reset whole process
/// 3: reset anon
/// 4: reset file
/// 5: reset PSS only
pub fn clear_process_refs(pid: u32, value: &str) -> std::io::Result<()> {
    let path = format!("/proc/{}/clear_refs", pid);
    std::fs::write(path, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_process_info() {
        let pid = std::process::id();
        let info = read_process_info(pid).expect("Failed to read current process info");

        assert_eq!(info.pid, pid);
        assert!(info.comm.len() > 0, "Command name should not be empty");

        let mem = info.mem_info.expect("Memory info should be present");

        // Assert reasonable values (at least something should be used)
        assert!(
            mem.rss > 0,
            "RSS should be greater than zero. RSS: {}",
            mem.rss
        );
        assert!(
            mem.anon > 0,
            "Anonymous memory should be greater than zero. Anon: {}",
            mem.anon
        );

        // Smaps rollup fields should also be set if supported
        // We only check for greater than 0 if they are indeed supported by the environment
        if std::path::Path::new(&format!("/proc/{}/smaps_rollup", pid)).exists() {
            assert!(
                mem.pss > 0,
                "PSS should be greater than zero on supporting systems"
            );
        }

        println!(
            "Process memory: RSS={}, Anon={}, PSS={}",
            mem.rss, mem.anon, mem.pss
        );
    }

    #[test]
    fn test_read_memory_info_fallbacks() {
        let pid = std::process::id();
        let mem = read_memory_info(pid).expect("Failed to read memory info");

        // Basic fields should be populated regardless of smaps_rollup support
        assert!(mem.rss > 0);
        assert!(mem.anon > 0);
    }
}
