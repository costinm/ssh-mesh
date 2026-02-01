//! Integration tests for the pmond crate
//!
//! These tests verify that the process monitor can:
//! - Start and monitor processes
//! - Handle HTTP requests for process information
//! - Detect new processes when they are started
//! - Handle WebSocket connections properly

use pmond::ProcMon;
use std::sync::Arc;
use std::time::Duration;

/// Test that we can get a specific process by PID
#[tokio::test]
async fn test_get_process_by_pid() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;
    let proc_mon = Arc::new(proc_mon);

    // Start monitoring
    proc_mon.start(true, false, None)?; // Don't watch PSI for this test

    // Get current process ID
    let current_pid = std::process::id();

    // Try to get the current process
    if let Some(process_info) = proc_mon.get_process(current_pid) {
        assert_eq!(process_info.pid, current_pid, "PID should match");
        assert!(
            !process_info.comm.is_empty(),
            "Process should have a command name"
        );
        println!(
            "Found current process: {} (PID: {})",
            process_info.comm, process_info.pid
        );
    } else {
        // If we can't get the current process, try to get the init process (PID 1)
        if let Some(process_info) = proc_mon.get_process(1) {
            assert_eq!(process_info.pid, 1, "PID should be 1");
            assert!(
                !process_info.comm.is_empty(),
                "Process should have a command name"
            );
            println!(
                "Found init process: {} (PID: {})",
                process_info.comm, process_info.pid
            );
        } else {
            panic!("Could not find current process or init process");
        }
    }

    // Stop monitoring
    proc_mon.stop()?;

    Ok(())
}

/// Test that we can get all cgroups and their memory info
#[tokio::test]
async fn test_cgroups_retrieval() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;
    let proc_mon = Arc::new(proc_mon);

    // Start monitoring
    proc_mon.start(true, false, None)?; // Don't watch PSI for this test

    // Give it a moment to read existing processes
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Get all cgroups
    let cgroups = proc_mon.get_all_cgroups();

    // We should have at least some cgroups if running on a real Linux system with cgroups v2
    println!("Found {} cgroups", cgroups.len());

    // If not empty, verify some data
    for (path, _info) in cgroups.iter() {
        assert!(
            path.starts_with("/sys/fs/cgroup"),
            "Cgroup path should start with /sys/fs/cgroup"
        );
    }

    // Stop monitoring
    proc_mon.stop()?;

    Ok(())
}
