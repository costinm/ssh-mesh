//! Unified method definitions for HTTP and MCP interfaces.
//!
//! This module provides the dispatch layer for API methods. Argument types
//! are defined in lib.rs, this module handles routing and schema generation.

use crate::proc::ProcMon;
use crate::{
    CgroupHighArgs, ClearRefsArgs, GetCgroupArgs, GetProcessArgs, ListCgroupsArgs,
    ListProcessesArgs, MoveProcessArgs, ProcessInfo, PsiWatchesArgs,
};
use schemars::schema_for;
use serde_json::{json, Value};

// ============================================================================
// Method Definition
// ============================================================================

/// A method definition that can be exposed via HTTP and MCP
pub struct MethodDef {
    pub name: &'static str,
    pub description: &'static str,
    /// Generate the JSON Schema for this method's arguments
    pub schema_fn: fn() -> Value,
    /// Execute the method with the given JSON arguments
    pub handler: fn(&ProcMon, Value) -> Result<Value, MethodError>,
}

/// Error type for method execution
#[derive(Debug)]
pub struct MethodError {
    pub code: i32,
    pub message: String,
}

impl std::fmt::Display for MethodError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for MethodError {}

impl MethodError {
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: msg.into(),
        }
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            code: -32001,
            message: msg.into(),
        }
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            code: -32000,
            message: msg.into(),
        }
    }

    pub fn method_not_found(name: &str) -> Self {
        Self {
            code: -32601,
            message: format!("Method not found: {}", name),
        }
    }
}

// ============================================================================
// Method Implementations
// ============================================================================

fn handle_list_processes(proc_mon: &ProcMon, _args: Value) -> Result<Value, MethodError> {
    let processes = proc_mon.get_all_processes(1);
    let process_list: Vec<&ProcessInfo> = processes.values().collect();
    Ok(json!(process_list))
}

fn handle_get_process(proc_mon: &ProcMon, args: Value) -> Result<Value, MethodError> {
    let args: GetProcessArgs =
        serde_json::from_value(args).map_err(|e| MethodError::invalid_params(e.to_string()))?;

    let pid: u32 = args
        .process
        .parse()
        .map_err(|_| MethodError::invalid_params(format!("Invalid PID: {}", args.process)))?;

    match proc_mon.get_process(pid) {
        Some(process) => Ok(json!(process)),
        None => Err(MethodError::not_found(format!("Process {} not found", pid))),
    }
}

fn handle_list_cgroups(proc_mon: &ProcMon, _args: Value) -> Result<Value, MethodError> {
    let cgroups = proc_mon.get_all_cgroups();
    Ok(json!(cgroups))
}

fn handle_get_cgroup(proc_mon: &ProcMon, args: Value) -> Result<Value, MethodError> {
    let args: GetCgroupArgs =
        serde_json::from_value(args).map_err(|e| MethodError::invalid_params(e.to_string()))?;

    match proc_mon.read_cgroup(&args.path) {
        Some(cgroup) => Ok(json!(cgroup)),
        None => Err(MethodError::not_found(format!(
            "Cgroup {} not found",
            args.path
        ))),
    }
}

fn handle_move_process(proc_mon: &ProcMon, args: Value) -> Result<Value, MethodError> {
    let args: MoveProcessArgs =
        serde_json::from_value(args).map_err(|e| MethodError::invalid_params(e.to_string()))?;

    proc_mon
        .move_process_to_cgroup(args.pid, args.cgroup_name)
        .map_err(|e| MethodError::internal(e.to_string()))?;

    Ok(json!({"status": "ok"}))
}

fn handle_clear_refs(proc_mon: &ProcMon, args: Value) -> Result<Value, MethodError> {
    let args: ClearRefsArgs =
        serde_json::from_value(args).map_err(|e| MethodError::invalid_params(e.to_string()))?;

    proc_mon
        .clear_refs(args.pid, &args.value)
        .map_err(|e| MethodError::internal(e.to_string()))?;

    Ok(json!({
        "status": "ok",
        "message": format!("Cleared refs for process {} with value {}", args.pid, args.value)
    }))
}

fn handle_cgroup_high(proc_mon: &ProcMon, args: Value) -> Result<Value, MethodError> {
    let args: CgroupHighArgs =
        serde_json::from_value(args).map_err(|e| MethodError::invalid_params(e.to_string()))?;

    proc_mon
        .adjust_cgroup_memory_high(args.path, args.percentage, args.interval)
        .map_err(|e| MethodError::internal(e.to_string()))?;

    Ok(json!({"status": "ok"}))
}

fn handle_psi_watches(proc_mon: &ProcMon, _args: Value) -> Result<Value, MethodError> {
    let watches = proc_mon.get_psi_watches();
    Ok(json!(watches))
}

// ============================================================================
// Method Registry
// ============================================================================

/// All available methods
pub static METHODS: &[MethodDef] = &[
    MethodDef {
        name: "list_processes",
        description: "List all running processes",
        schema_fn: || serde_json::to_value(schema_for!(ListProcessesArgs)).unwrap(),
        handler: handle_list_processes,
    },
    MethodDef {
        name: "get_process",
        description: "Get details of a specific process by PID",
        schema_fn: || serde_json::to_value(schema_for!(GetProcessArgs)).unwrap(),
        handler: handle_get_process,
    },
    MethodDef {
        name: "list_cgroups",
        description: "List all cgroups used by processes",
        schema_fn: || serde_json::to_value(schema_for!(ListCgroupsArgs)).unwrap(),
        handler: handle_list_cgroups,
    },
    MethodDef {
        name: "get_cgroup",
        description: "Get memory info for a specific cgroup path",
        schema_fn: || serde_json::to_value(schema_for!(GetCgroupArgs)).unwrap(),
        handler: handle_get_cgroup,
    },
    MethodDef {
        name: "move_process",
        description: "Move a process to a new cgroup subdirectory",
        schema_fn: || serde_json::to_value(schema_for!(MoveProcessArgs)).unwrap(),
        handler: handle_move_process,
    },
    MethodDef {
        name: "clear_refs",
        description: "Clear process memory references (PSS, etc) via /proc/[pid]/clear_refs. Values: 1 (PSS/soft-dirty), 2 (whole process), 3 (anon), 4 (file), 5 (PSS only)",
        schema_fn: || serde_json::to_value(schema_for!(ClearRefsArgs)).unwrap(),
        handler: handle_clear_refs,
    },
    MethodDef {
        name: "cgroup_high",
        description: "Adjust memory.high for a cgroup to a percentage of current usage",
        schema_fn: || serde_json::to_value(schema_for!(CgroupHighArgs)).unwrap(),
        handler: handle_cgroup_high,
    },
    MethodDef {
        name: "psi_watches",
        description: "Get current PSI (Pressure Stall Information) watches and their status",
        schema_fn: || serde_json::to_value(schema_for!(PsiWatchesArgs)).unwrap(),
        handler: handle_psi_watches,
    },
];

/// Find a method by name
pub fn find_method(name: &str) -> Option<&'static MethodDef> {
    METHODS.iter().find(|m| m.name == name)
}

/// Execute a method by name with the given arguments
pub fn call_method(proc_mon: &ProcMon, name: &str, args: Value) -> Result<Value, MethodError> {
    match find_method(name) {
        Some(method) => (method.handler)(proc_mon, args),
        None => Err(MethodError::method_not_found(name)),
    }
}
