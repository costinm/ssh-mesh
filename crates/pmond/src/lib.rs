//! Process monitoring utilities for reading process and memory information from `/proc` and cgroups.
//!
//! This module provides:
//! - [`ProcessInfo`]: Information about a running process
//! - [`ProcMemInfo`]: Memory statistics from `/proc/[pid]` or cgroups
//! - [`ProcMon`]: Process monitor for tracking process lifecycle
//! - Helper functions for reading process details from procfs

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::trace;

pub mod handlers;
pub mod methods;
pub mod proc;
pub mod proc_netlink;
pub mod psi;

pub use proc::ProcMon;

/// Base path for procfs
const PROC_BASE: &str = "/proc";
/// Base path for cgroup2 filesystem
const CGROUP_BASE: &str = "/sys/fs/cgroup";

/// Read process name from /proc/[pid]/comm
pub fn read_comm(pid: u32) -> String {
    let comm_path = format!("/proc/{}/comm", pid);
    std::fs::read_to_string(comm_path)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "(unknown)".to_string())
}

pub use read_process_info as read_process_info_from_proc;

#[derive(Serialize, Deserialize, Debug, Clone, Default, JsonSchema)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub cgroup_path: Option<String>,
    pub cmdline: Option<String>,
    pub mem_info: Option<ProcMemInfo>,
    pub uid: Option<u32>,
}

// ============================================================================
// API Argument Types (used by HTTP, MCP, and handlers)
// ============================================================================

/// Arguments for list_processes - no parameters needed
#[derive(Deserialize, JsonSchema, Default)]
pub struct ListProcessesArgs {}

/// Arguments for get_process
#[derive(Deserialize, JsonSchema)]
pub struct GetProcessArgs {
    /// Process ID or name to look up
    pub process: String,
}

/// Arguments for list_cgroups - no parameters needed
#[derive(Deserialize, JsonSchema, Default)]
pub struct ListCgroupsArgs {}

/// Arguments for get_cgroup
#[derive(Deserialize, JsonSchema)]
pub struct GetCgroupArgs {
    /// Full cgroup path
    pub path: String,
}

/// Arguments for move_process
#[derive(Deserialize, JsonSchema)]
pub struct MoveProcessArgs {
    /// Process ID to move
    pub pid: u32,
    /// Target cgroup name (None for default)
    pub cgroup_name: Option<String>,
}

/// Arguments for clear_refs
#[derive(Deserialize, JsonSchema)]
pub struct ClearRefsArgs {
    /// Process ID
    pub pid: u32,
    /// Value to write: "1"-"5" or "7" for all
    pub value: String,
}

/// Arguments for cgroup_high
#[derive(Deserialize, JsonSchema)]
pub struct CgroupHighArgs {
    /// Full cgroup path
    pub path: String,
    /// Percentage of current memory to set as high (0-100)
    pub percentage: f64,
    /// Seconds before resetting to max (0 = no reset)
    pub interval: u64,
}

/// Arguments for psi_watches - no parameters needed
#[derive(Deserialize, JsonSchema, Default)]
pub struct PsiWatchesArgs {}

#[derive(Debug, Clone)]
pub enum MonitoringEvent {
    Netlink(crate::proc_netlink::NetlinkEvent),
    Pressure(crate::psi::PressureEvent),
}

/// Memory info for a process or cgroup. Each field should have a comment indicating
/// where it is derived from.
#[derive(Serialize, Deserialize, Debug, Clone, Default, JsonSchema)]
pub struct ProcMemInfo {
    // --- Delta Fields  ---
    /// Anonymous memory. Process: smaps_rollup (Anonymous), status (RssAnon), or statm. Cgroup: memory.stat (anon).
    pub d_anon: i64,
    /// File-backed memory. Process: Derived (rss - anon) or status (RssFile). Cgroup: memory.stat (file).
    pub d_file: i64,
    /// Kernel stack memory. Process: status (VmStk). Cgroup: memory.stat (kernel_stack).
    pub d_kernel_stack: i64,
    /// Page table entries. Process: status (VmPTE). Cgroup: memory.stat (pagetables).
    pub d_pagetables: i64,
    /// Shared memory. Process: status (RssShmem) or statm (shared). Cgroup: memory.stat (shmem).
    pub d_shmem: i64,
    /// Page faults. Process: stat (minflt + majflt). Cgroup: memory.stat (pgfault).
    pub d_pgfault: i64,
    /// Major page faults. Process: stat (majflt). Cgroup: memory.stat (pgmajfault).
    pub d_pgmajfault: i64,

    // --- Common Fields (Both Process and Cgroup) ---
    /// Anonymous memory. Process: smaps_rollup (Anonymous), status (RssAnon), or statm. Cgroup: memory.stat (anon).
    pub anon: u64,
    /// File-backed memory. Process: Derived (rss - anon) or status (RssFile). Cgroup: memory.stat (file).
    /// statm[3] is file + shmem
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
    // VmExec - exec size - statm[4]
    /// Proportional Set Size. Process: smaps_rollup (Pss). Cgroup: N/A.
    pub pss: u64,
    /// Total Resident Set Size. Process: smaps_rollup (Rss), status (VmRSS), or statm[2]. Cgroup: N/A (see memory_current).
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

/// Macro to reduce boilerplate in `ProcMemInfo::merge()`
macro_rules! merge_field {
    ($self:ident, $other:ident, $field:ident) => {
        if $self.$field == 0 {
            $self.$field = $other.$field;
        }
    };
    ($self:ident, $other:ident, $field:ident, option) => {
        if $self.$field.is_none() {
            $self.$field = $other.$field.clone();
        }
    };
}

impl ProcMemInfo {
    /// Merge fields from another ProcMemInfo if they are zero or None in this one.
    pub fn merge(&mut self, other: &ProcMemInfo) {
        // Common fields
        merge_field!(self, other, anon);
        merge_field!(self, other, file);
        merge_field!(self, other, kernel_stack);
        merge_field!(self, other, pagetables);
        merge_field!(self, other, shmem);
        merge_field!(self, other, pgfault);
        merge_field!(self, other, pgmajfault);

        // Process-only fields
        merge_field!(self, other, pss);
        merge_field!(self, other, rss);
        merge_field!(self, other, private_clean);
        merge_field!(self, other, private_dirty);
        merge_field!(self, other, shared_clean);
        merge_field!(self, other, shared_dirty);
        merge_field!(self, other, referenced);
        merge_field!(self, other, swap);
        merge_field!(self, other, hugetlb);

        // Cgroup-only fields
        merge_field!(self, other, kernel);
        merge_field!(self, other, file_mapped);
        merge_field!(self, other, file_dirty);
        merge_field!(self, other, file_writeback);
        merge_field!(self, other, swapcached);
        merge_field!(self, other, pgrefill);
        merge_field!(self, other, pgactivate);
        merge_field!(self, other, pgdeactivate);
        merge_field!(self, other, pswpin);
        merge_field!(self, other, pswpout);
        merge_field!(self, other, pgsteal);
        merge_field!(self, other, pgscan);
        merge_field!(self, other, pgdemote_kswapd);
        merge_field!(self, other, pgdemote_direct);
        merge_field!(self, other, pgdemote_khugepaged);
        merge_field!(self, other, pgdemote_proactive);
        merge_field!(self, other, active_anon);
        merge_field!(self, other, active_file);
        merge_field!(self, other, inactive_anon);
        merge_field!(self, other, inactive_file);
        merge_field!(self, other, workingset_refault_anon);
        merge_field!(self, other, workingset_refault_file);
        merge_field!(self, other, workingset_activate_anon);
        merge_field!(self, other, workingset_activate_file);
        merge_field!(self, other, workingset_restore_anon);
        merge_field!(self, other, workingset_restore_file);
        merge_field!(self, other, workingset_nodereclaim);

        // Option fields
        merge_field!(self, other, memory_current, option);
        merge_field!(self, other, memory_high, option);
    }
}

/// Read process information from /proc/[pid]/stat (static version for global access)
pub fn read_process_info(pid: u32) -> Result<ProcessInfo, Box<dyn std::error::Error>> {
    read_process_info_impl(pid)
}

pub fn read_process_info_impl(pid: u32) -> Result<ProcessInfo, Box<dyn std::error::Error>> {
    let stat_path = format!("{}/{}/stat", PROC_BASE, pid);
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
    let cgroup_file = format!("{}/{}/cgroup", PROC_BASE, pid);
    match std::fs::read_to_string(&cgroup_file) {
        Ok(content) => {
            for line in content.lines() {
                if line.starts_with("0::") {
                    let cgroup = &line[3..];
                    if cgroup == "/" {
                        return Some(CGROUP_BASE.to_string());
                    } else if !cgroup.is_empty() {
                        return Some(format!("{}{}", CGROUP_BASE, cgroup));
                    }
                }
            }
            None
        }
        Err(e) => {
            trace!("Failed to read {}: {}", cgroup_file, e);
            None
        }
    }
}

/// Read memory information for a process from /proc/[pid]/smaps_rollup, /proc/[pid]/status, /proc/[pid]/stat and /proc/[pid]/statm as fallback
pub fn read_memory_info(pid: u32) -> Option<ProcMemInfo> {
    let mut mem_info = ProcMemInfo::default();
    let mut found_any = false;

    // Read fault statistics from /proc/[pid]/stat
    found_any |= read_fault_stats(pid, &mut mem_info);

    // Read PSS/RSS from smaps_rollup (most accurate)
    found_any |= read_smaps_rollup(pid, &mut mem_info);

    // Read additional fields from status
    found_any |= read_proc_status_memory(pid, &mut mem_info);

    // Fallback to statm for basic RSS/anon
    if !found_any || (mem_info.anon == 0 && mem_info.rss == 0) {
        found_any |= read_statm_fallback(pid, &mut mem_info);
    }

    if found_any {
        // Merge cgroup stats if process has a dedicated cgroup (-PID.scope)
        if let Some(cg_path) = read_cgroup_path(pid) {
            let expected_suffix = format!("-{}.scope", pid);
            if cg_path.ends_with(&expected_suffix) {
                if let Ok(cg_info) = read_cgroup_info(&cg_path) {
                    mem_info.merge(&cg_info);
                }
            }
        }
        Some(mem_info)
    } else {
        None
    }
}

/// Read page fault statistics from /proc/[pid]/stat
fn read_fault_stats(pid: u32, mem_info: &mut ProcMemInfo) -> bool {
    let stat_path = format!("{}/{}/stat", PROC_BASE, pid);
    match std::fs::read_to_string(&stat_path) {
        Ok(content) => {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() >= 12 {
                // Field 10 is minflt, 12 is majflt (0-indexed: 9, 11)
                let min_faults: u64 = parts[9].parse().unwrap_or(0);
                let maj_faults: u64 = parts[11].parse().unwrap_or(0);
                mem_info.pgfault = min_faults + maj_faults;
                mem_info.pgmajfault = maj_faults;
                true
            } else {
                false
            }
        }
        Err(e) => {
            trace!("Failed to read {}: {}", stat_path, e);
            false
        }
    }
}

/// Read PSS and RSS breakdown from /proc/[pid]/smaps_rollup
fn read_smaps_rollup(pid: u32, mem_info: &mut ProcMemInfo) -> bool {
    let rollup_path = format!("{}/{}/smaps_rollup", PROC_BASE, pid);
    match std::fs::read_to_string(&rollup_path) {
        Ok(content) => {
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
            if rollup_found && mem_info.rss > mem_info.anon {
                mem_info.file = mem_info.rss - mem_info.anon;
            }
            rollup_found
        }
        Err(e) => {
            trace!("Failed to read {}: {}", rollup_path, e);
            false
        }
    }
}

/// Read memory fields from /proc/[pid]/status (VmPTE, VmStk, RssShmem, etc.)
fn read_proc_status_memory(pid: u32, mem_info: &mut ProcMemInfo) -> bool {
    let status_path = format!("{}/{}/status", PROC_BASE, pid);
    match std::fs::read_to_string(&status_path) {
        Ok(content) => {
            let mut found = false;
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
                            found = true;
                        }
                        "RssFile" if mem_info.file == 0 => {
                            mem_info.file = val_kb * 1024;
                            found = true;
                        }
                        "RssShmem" => {
                            mem_info.shmem = val_kb * 1024;
                            found = true;
                        }
                        "VmPTE" => {
                            mem_info.pagetables = val_kb * 1024;
                            found = true;
                        }
                        "VmStk" => {
                            mem_info.kernel_stack = val_kb * 1024;
                            found = true;
                        }
                        "VmSwap" if mem_info.swap == 0 => {
                            mem_info.swap = val_kb * 1024;
                            found = true;
                        }
                        "VmRSS" if mem_info.rss == 0 => {
                            mem_info.rss = val_kb * 1024;
                            found = true;
                        }
                        "HugetlbPages" => {
                            mem_info.hugetlb = val_kb * 1024;
                            found = true;
                        }
                        _ => (),
                    }
                }
            }
            found
        }
        Err(e) => {
            trace!("Failed to read {}: {}", status_path, e);
            false
        }
    }
}

/// Read basic RSS from /proc/[pid]/statm
/// This should be faster - but has limitted information.
///
/// Useful:
/// - RSS (2) - total, anon + file + others
/// - SHARED == FILE + Shmem (3)
/// - TEXT/code (4) - VmExe + VmLib
/// - DATA+stack (6)
fn read_statm_fallback(pid: u32, mem_info: &mut ProcMemInfo) -> bool {
    let statm_path = format!("{}/{}/statm", PROC_BASE, pid);
    match std::fs::read_to_string(&statm_path) {
        Ok(content) => {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() >= 3 {
                let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
                if page_size > 0 {
                    let resident_pages: u64 = parts[1].parse().unwrap_or(0);
                    let shared_pages: u64 = parts[2].parse().unwrap_or(0);
                    let mut found = false;

                    if mem_info.rss == 0 {
                        mem_info.rss = resident_pages * page_size;
                        found = true;
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
                        found = true;
                    }
                    return found;
                }
            }
            false
        }
        Err(e) => {
            trace!("Failed to read {}: {}", statm_path, e);
            false
        }
    }
}

/// Read cmdline for a process
pub fn read_cmdline(pid: u32) -> Option<String> {
    let cmdline_path = format!("{}/{}/cmdline", PROC_BASE, pid);
    match std::fs::read_to_string(&cmdline_path) {
        Ok(content) if !content.is_empty() => {
            let cmdline = content.replace("\0", " ").trim_end().to_string();
            if !cmdline.is_empty() {
                Some(cmdline)
            } else {
                None
            }
        }
        Ok(_) => None,
        Err(e) => {
            trace!("Failed to read {}: {}", cmdline_path, e);
            None
        }
    }
}

/// Read exe (symbolic link target) for a process
pub fn read_exe(pid: u32) -> Option<String> {
    let exe_path = format!("{}/{}/exe", PROC_BASE, pid);
    match std::fs::read_link(&exe_path) {
        Ok(target) => Some(target.to_string_lossy().to_string()),
        Err(e) => {
            trace!("Failed to read {}: {}", exe_path, e);
            None
        }
    }
}

/// Read UID for a process from /proc/[pid]/status
pub fn read_process_uid(pid: u32) -> Option<u32> {
    let status_path = format!("{}/{}/status", PROC_BASE, pid);
    match std::fs::read_to_string(&status_path) {
        Ok(content) => {
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
            None
        }
        Err(e) => {
            trace!("Failed to read {}: {}", status_path, e);
            None
        }
    }
}

/// Create ProcessInfo for a given PID, including cgroup information
pub fn create_process_info(pid: u32) -> Result<ProcessInfo, Box<dyn std::error::Error>> {
    read_process_info_impl(pid)
}

/// Parse memory statistics from a cgroup path
pub fn read_cgroup_info(cgroup_path: &str) -> Result<ProcMemInfo, Box<dyn std::error::Error>> {
    // TODO: take ProcMemInfo as a param
    // TODO: bool to indicate only cgroup-unique fields should be processed.
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
/// 1: reset referenced
/// 2: reset anonymous memory pages only
/// 3: reset file backed
/// 4: reset dirty (find how many pages are written to)
/// 5: reset 'peak memory'
/// 6: reset huge pages
/// 7: all of the above.
pub fn clear_process_refs(pid: u32, value: &str) -> std::io::Result<()> {
    let path = format!("/proc/{}/clear_refs", pid);
    if value.eq("7") {
        std::fs::write(path.clone(), "1")?;
        std::fs::write(path.clone(), "2")?;
        std::fs::write(path.clone(), "3")?;
        std::fs::write(path.clone(), "4")?;
        std::fs::write(path, "5")
    } else {
        std::fs::write(path, value)
    }
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
