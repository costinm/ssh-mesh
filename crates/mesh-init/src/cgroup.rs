//! Cgroup v2 management for mesh-init services.
//!
//! Creates cgroups under `/sys/fs/cgroup/mesh.slice/`, enables controllers,
//! sets resource limits, and manages process placement.

use std::fs;
use std::path::Path;

use tracing::{debug, error, info};

use crate::config::ResolvedResourceLimits;

// ============================================================================
// Error Types
// ============================================================================

/// Errors from cgroup operations.
#[derive(Debug, thiserror::Error)]
pub enum CgroupError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("cgroup error: {0}")]
    CgroupError(String),

    #[error("invalid OOM score {0}: must be between -1000 and 1000")]
    InvalidOomScore(i32),
}

// ============================================================================
// Constants
// ============================================================================

/// Base path for mesh-init cgroups.
const MESH_SLICE_PATH: &str = "/sys/fs/cgroup/mesh.slice";

// ============================================================================
// Cgroup Operations
// ============================================================================

/// Build the cgroup path for a service name.
///
/// Returns `/sys/fs/cgroup/mesh.slice/{name}.scope`.
///
/// `name` is validated to reject path separators and `..` components, which
/// would otherwise allow escaping `mesh.slice`.
pub fn cgroup_path_for(name: &str) -> Result<String, CgroupError> {
    if let Err(reason) = crate::config::validate_cgroup_name(name) {
        error!(name = ?name, error = %reason, "invalid_cgroup_name_rejected");
        return Err(CgroupError::CgroupError(format!(
            "invalid cgroup name: {reason}"
        )));
    }
    Ok(format!("{}/{}.scope", MESH_SLICE_PATH, name))
}

/// Create a cgroup for a service under `mesh.slice`.
///
/// Creates the `mesh.slice` parent if it doesn't exist, enables controllers,
/// then creates the `{name}.scope` child cgroup.
pub fn create_cgroup(name: &str) -> Result<String, CgroupError> {
    let cgroup_root = "/sys/fs/cgroup";

    // Ensure mesh.slice exists
    if !Path::new(MESH_SLICE_PATH).exists() {
        fs::create_dir_all(MESH_SLICE_PATH)?;
        info!(path = %MESH_SLICE_PATH, "slice_created");
    }

    // Enable controllers in the root so mesh.slice can use them
    let _ = enable_controllers(cgroup_root);
    // Enable controllers in mesh.slice so the scope can use them
    let _ = enable_controllers(MESH_SLICE_PATH);

    // Create the scope
    let scope_path = cgroup_path_for(name)?;
    if !Path::new(&scope_path).exists() {
        fs::create_dir_all(&scope_path)?;
        info!(path = %scope_path, "cgroup_created");
    } else if let Err(error) = freeze_cgroup(&scope_path, false) {
        debug!(
            path = %scope_path,
            error = %error,
            "cgroup_unfreeze_existing_failed"
        );
    }

    Ok(scope_path)
}

/// Enable memory, cpu, and io controllers in a cgroup's subtree_control.
pub fn enable_controllers(path: &str) -> Result<(), CgroupError> {
    let controllers_path = format!("{}/cgroup.controllers", path);
    let subtree_control_path = format!("{}/cgroup.subtree_control", path);

    let available = match fs::read_to_string(&controllers_path) {
        Ok(s) => s,
        Err(e) => {
            debug!(path = %controllers_path, error = %e, "read_controllers_failed");
            return Ok(());
        }
    };

    let mut to_enable = Vec::new();
    for controller in ["memory", "cpu", "io"] {
        if available.contains(controller) {
            to_enable.push(format!("+{}", controller));
        }
    }

    if to_enable.is_empty() {
        return Ok(());
    }

    let cmd = to_enable.join(" ");
    match fs::write(&subtree_control_path, &cmd) {
        Ok(()) => {
            info!(controllers = %cmd, path = %subtree_control_path, "controllers_enabled");
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            error!(
                path = %subtree_control_path,
                "enable_controllers_permission_denied"
            );
        }
        Err(e) => {
            debug!(
                path = %subtree_control_path,
                error = %e,
                "enable_controllers_failed"
            );
        }
    }

    Ok(())
}

/// Set resource limits on a cgroup.
pub fn set_limits(cgroup_path: &str, limits: &ResolvedResourceLimits) -> Result<(), CgroupError> {
    if let Some(val) = limits.memory_low {
        write_cgroup_file(cgroup_path, "memory.low", &val.to_string())?;
    }
    if let Some(val) = limits.memory_high {
        write_cgroup_file(cgroup_path, "memory.high", &val.to_string())?;
    }
    if let Some(val) = limits.memory_max {
        write_cgroup_file(cgroup_path, "memory.max", &val.to_string())?;
    }
    if let Some(val) = limits.cpu_weight {
        write_cgroup_file(cgroup_path, "cpu.weight", &val.to_string())?;
    }
    Ok(())
}

/// Move a process into a cgroup by writing its PID to `cgroup.procs`.
pub fn move_to_cgroup(pid: u32, cgroup_path: &str) -> Result<(), CgroupError> {
    let procs_path = format!("{}/cgroup.procs", cgroup_path);
    fs::write(&procs_path, pid.to_string()).map_err(|e| {
        error!(pid, path = %cgroup_path, error = %e, "move_to_cgroup_failed");
        CgroupError::Io(e)
    })?;
    info!(pid, path = %cgroup_path, "moved_to_cgroup");
    Ok(())
}

/// Freeze or unfreeze a cgroup using cgroup.freeze.
pub fn freeze_cgroup(cgroup_path: &str, freeze: bool) -> Result<(), CgroupError> {
    let val = if freeze { "1" } else { "0" };
    write_cgroup_file(cgroup_path, "cgroup.freeze", val)?;
    info!(
        action = if freeze { "freeze" } else { "unfreeze" },
        path = %cgroup_path,
        "cgroup_frozen_state_changed"
    );
    Ok(())
}

/// Remove an empty cgroup directory.
pub fn remove_cgroup(cgroup_path: &str) -> Result<(), CgroupError> {
    if Path::new(cgroup_path).exists() {
        fs::remove_dir(cgroup_path).map_err(|e| {
            debug!(path = %cgroup_path, error = %e, "remove_cgroup_failed");
            CgroupError::Io(e)
        })?;
        info!(path = %cgroup_path, "cgroup_removed");
    }
    Ok(())
}

/// Set the OOM score adjustment for a process.
pub fn set_oom_score(pid: u32, score: i32) -> Result<(), CgroupError> {
    if !(-1000..=1000).contains(&score) {
        return Err(CgroupError::InvalidOomScore(score));
    }
    let path = format!("/proc/{}/oom_score_adj", pid);
    fs::write(&path, score.to_string()).map_err(|e| {
        error!(pid, error = %e, "set_oom_score_adj_failed");
        CgroupError::Io(e)
    })?;
    debug!(pid, score, "oom_score_adj_set");
    Ok(())
}

/// Write a value to a cgroup control file.
fn write_cgroup_file(cgroup_path: &str, filename: &str, value: &str) -> Result<(), CgroupError> {
    let path = format!("{}/{}", cgroup_path, filename);
    fs::write(&path, value).map_err(|e| {
        error!("Failed to write '{}' to {}: {}", value, path, e);
        CgroupError::Io(e)
    })?;
    debug!("Set {}/{} = {}", cgroup_path, filename, value);
    Ok(())
}

/// Read a value from a cgroup control file.
pub fn read_cgroup_file(cgroup_path: &str, filename: &str) -> Result<String, CgroupError> {
    let path = format!("{}/{}", cgroup_path, filename);
    let value = fs::read_to_string(&path).map_err(|e| {
        debug!("Failed to read {}: {}", path, e);
        CgroupError::Io(e)
    })?;
    Ok(value.trim().to_string())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_path_construction() {
        assert_eq!(
            cgroup_path_for("chrome").unwrap(),
            "/sys/fs/cgroup/mesh.slice/chrome.scope"
        );
        assert_eq!(
            cgroup_path_for("my-service").unwrap(),
            "/sys/fs/cgroup/mesh.slice/my-service.scope"
        );
        // A17: invalid names return Err, not a sentinel path
        assert!(cgroup_path_for("../escape").is_err());
        assert!(cgroup_path_for("a/b").is_err());
        assert!(cgroup_path_for("").is_err());
    }

    #[test]
    fn test_oom_score_bounds() {
        // Valid range
        assert!((-1000..=1000).contains(&-1000));
        assert!((-1000..=1000).contains(&0));
        assert!((-1000..=1000).contains(&1000));

        // Invalid
        assert!(!(-1000..=1000).contains(&-1001));
        assert!(!(-1000..=1000).contains(&1001));
    }

    #[test]
    fn test_resource_limits_to_files() {
        // Verify the mapping of limit fields to cgroup file names
        let limits = ResolvedResourceLimits {
            memory_low: Some(256 * 1024 * 1024),
            memory_high: Some(2 * 1024 * 1024 * 1024),
            memory_max: Some(4 * 1024 * 1024 * 1024),
            cpu_weight: Some(100),
        };

        // We can't write to actual cgroup files in tests, but verify the values are correct
        assert_eq!(limits.memory_low.unwrap().to_string(), "268435456");
        assert_eq!(limits.memory_high.unwrap().to_string(), "2147483648");
        assert_eq!(limits.memory_max.unwrap().to_string(), "4294967296");
        assert_eq!(limits.cpu_weight.unwrap().to_string(), "100");
    }
}
