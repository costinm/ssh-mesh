use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info};

use crate::{ProcMon, ProcessDetailedInfo};

/// JSON-lines request methods for pmond.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum Request {
    #[serde(rename = "ps", alias = "list_processes")]
    Processes,
    #[serde(rename = "process", alias = "get_process")]
    Process { pid: u32 },
    #[serde(rename = "process_only", alias = "ps_one")]
    ProcessOnly { pid: u32 },
    #[serde(rename = "cgroup", alias = "get_cgroup")]
    Cgroup { path: String },
    #[serde(rename = "cgroups", alias = "list_cgroups")]
    Cgroups,
    #[serde(rename = "psi", alias = "psi_watches")]
    Psi,
    #[serde(rename = "cgroup_high")]
    CgroupHigh {
        path: String,
        percentage: f64,
        interval: u64,
    },
    #[serde(rename = "cgroup_procs")]
    CgroupProcs { path: String },
    #[serde(rename = "move_process")]
    MoveProcess {
        pid: u32,
        cgroup_name: Option<String>,
    },
    #[serde(rename = "clear_refs")]
    ClearRefs { pid: u32, value: String },
    #[serde(rename = "freeze_process")]
    FreezeProcess { pid: u32, freeze: bool },
    #[serde(rename = "freeze_cgroup")]
    FreezeCgroup { path: String, freeze: bool },
}

/// Reusable pmond command service.
pub struct PmondService {
    proc_mon: Arc<ProcMon>,
}

impl PmondService {
    /// Create a service around an initialized process monitor.
    pub fn new(proc_mon: Arc<ProcMon>) -> Self {
        Self { proc_mon }
    }

    /// Handle a single JSON-lines request.
    pub async fn handle_request(&self, request: Request) -> mesh::protocol::Response {
        match request {
            Request::Processes => {
                info!("pmond ps");
                let processes = self.proc_mon.get_all_processes(1);
                let process_list = processes.into_values().collect::<Vec<_>>();
                mesh::protocol::Response::ok_with_data(json!(process_list))
            }
            Request::Process { pid } => {
                debug!(pid, "pmond process");
                match self.proc_mon.get_process(pid) {
                    Some(process) => {
                        let cgroup = process
                            .cgroup_path
                            .as_ref()
                            .and_then(|p| crate::read_cgroup_detailed(p));
                        let parent_cgroups = process
                            .cgroup_path
                            .as_ref()
                            .map(|p| crate::get_parent_cgroups(p))
                            .unwrap_or_default();
                        mesh::protocol::Response::ok_with_data(json!(ProcessDetailedInfo {
                            process,
                            cgroup,
                            parent_cgroups,
                        }))
                    }
                    None => mesh::protocol::Response::err(format!("process {pid} not found")),
                }
            }
            Request::ProcessOnly { pid } => match self.proc_mon.get_process(pid) {
                Some(process) => mesh::protocol::Response::ok_with_data(json!(process)),
                None => mesh::protocol::Response::err(format!("process {pid} not found")),
            },
            Request::Cgroup { path } => match crate::read_cgroup_detailed(&path) {
                Some(cgroup) => mesh::protocol::Response::ok_with_data(json!(cgroup)),
                None => mesh::protocol::Response::err(format!("cgroup {path} not found")),
            },
            Request::Cgroups => {
                let cgroups = self.proc_mon.get_all_cgroups();
                mesh::protocol::Response::ok_with_data(json!(cgroups))
            }
            Request::Psi => {
                let watches = self.proc_mon.get_psi_watches();
                mesh::protocol::Response::ok_with_data(json!(watches))
            }
            Request::CgroupHigh {
                path,
                percentage,
                interval,
            } => {
                match self
                    .proc_mon
                    .adjust_cgroup_memory_high(path, percentage, interval)
                {
                    Ok(()) => mesh::protocol::Response::ok(),
                    Err(e) => mesh::protocol::Response::err(e.to_string()),
                }
            }
            Request::CgroupProcs { path } => {
                let processes = self.proc_mon.get_processes_in_cgroup(&path);
                mesh::protocol::Response::ok_with_data(json!(processes))
            }
            Request::MoveProcess { pid, cgroup_name } => {
                match self.proc_mon.move_process_to_cgroup(pid, cgroup_name) {
                    Ok(()) => mesh::protocol::Response::ok(),
                    Err(e) => mesh::protocol::Response::err(e.to_string()),
                }
            }
            Request::ClearRefs { pid, value } => match self.proc_mon.clear_refs(pid, &value) {
                Ok(()) => mesh::protocol::Response::ok_with_data(json!({
                    "message": format!("Cleared refs for process {} with value {}", pid, value)
                })),
                Err(e) => mesh::protocol::Response::err(e.to_string()),
            },
            Request::FreezeProcess { pid, freeze } => {
                match self.proc_mon.freeze_process(pid, freeze) {
                    Ok(()) => mesh::protocol::Response::ok(),
                    Err(e) => mesh::protocol::Response::err(e.to_string()),
                }
            }
            Request::FreezeCgroup { path, freeze } => {
                match self.proc_mon.freeze_cgroup(&path, freeze) {
                    Ok(()) => mesh::protocol::Response::ok(),
                    Err(e) => mesh::protocol::Response::err(e.to_string()),
                }
            }
        }
    }
}
