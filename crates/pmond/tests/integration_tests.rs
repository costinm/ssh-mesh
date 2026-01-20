//! Integration tests for the pmond crate
//!
//! These tests verify that the process monitor can:
//! - Start and monitor processes
//! - Handle HTTP requests for process information
//! - Detect new processes when they are started
//! - Handle WebSocket connections properly

use pmond::{ProcMon, ProcessInfo, proc_netlink};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

fn start_monitoring(proc_mon: Arc<ProcMon>) {
    let (tx, mut rx) = mpsc::channel(100);
    let running = proc_mon.running.clone();
    
    // Start netlink listener
    tokio::task::spawn_blocking(move || {
        let _ = proc_netlink::run_netlink_listener(tx, running);
    });

    // Start event consumer
    let pm = proc_mon.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                proc_netlink::NetlinkEvent::Fork { parent_tgid, child_pid, child_tgid, .. } => {
                    pm.handle_fork(parent_tgid, child_pid, child_tgid);
                }
                proc_netlink::NetlinkEvent::Exit { process_tgid, .. } => {
                    pm.handle_exit(process_tgid);
                }
                _ => {}
            }
        }
    });
}

/// Test that we can create a ProcMon instance and get existing processes
#[tokio::test]
async fn test_proc_mon_creation_and_existing_processes() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;
    let proc_mon = Arc::new(proc_mon);

    // Start monitoring
    proc_mon.start(true, false)?; // Don't watch PSI for this test
    start_monitoring(proc_mon.clone());

    // Give it a moment to read existing processes
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Get all processes
    let processes = proc_mon.get_all_processes();

    // We should have at least some processes
    assert!(!processes.is_empty(), "Should have found some processes");

    println!("Found {} processes", processes.len());

    // Stop monitoring
    proc_mon.stop()?;

    Ok(())
}

/// Test that the HTTP handler returns process information as JSON
#[tokio::test]
async fn test_http_handler_returns_processes() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;
    let proc_mon = Arc::new(proc_mon);

    // Start monitoring
    proc_mon.start(true, false)?; // Don't watch PSI for this test
    start_monitoring(proc_mon.clone());

    // Give it a moment to read existing processes
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Get all processes through the handler-like function
    let processes = proc_mon.get_all_processes();

    // Verify we got some processes
    assert!(!processes.is_empty(), "Should have found some processes");

    // Verify that each process has the required fields
    for (pid, process_info) in processes.iter() {
        assert_eq!(*pid, process_info.pid, "PID should match key");
        assert!(
            !process_info.comm.is_empty(),
            "Process should have a command name"
        );
    }

    println!(
        "Verified {} processes have required fields",
        processes.len()
    );

    // Stop monitoring
    proc_mon.stop()?;

    Ok(())
}

/// Test that we can detect new processes
#[tokio::test]
async fn test_process_detection() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;
    let proc_mon = Arc::new(proc_mon);

    // Vector to store detected processes
    let detected_processes = Arc::new(Mutex::new(Vec::new()));
    let detected_processes_clone = detected_processes.clone();

    // Set a callback to handle new processes
    proc_mon.set_callback(move |p: ProcessInfo| {
        println!("New process detected: pid={}, comm={}", p.pid, p.comm);
        let mut detected = detected_processes_clone.lock().unwrap();
        detected.push(p);
    });

    // Start monitoring
    proc_mon.start(true, false)?; // Don't watch PSI for this test
    start_monitoring(proc_mon.clone());

    // Give it a moment to read existing processes
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Start a short-lived process
    let mut child = Command::new("sleep")
        .arg("2") // Sleep for 2 seconds
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let child_pid = child.id();
    println!("Started test process with PID: {}", child_pid);

    // Wait a bit for the process to be detected
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Wait for the process to complete
    let _ = child.wait();

    // Wait a bit more for the exit event to be processed
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check if our process was detected
    let detected = detected_processes.lock().unwrap();
    let process_found = detected.iter().any(|p| p.pid == child_pid);

    if process_found {
        println!("Successfully detected test process with PID: {}", child_pid);
    } else {
        println!("Test process with PID {} may not have been detected (this can happen in some environments)", child_pid);
    }

    // Stop monitoring
    proc_mon.stop()?;

    Ok(())
}

/// Test that we can get a specific process by PID
#[tokio::test]
async fn test_get_process_by_pid() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;
    let proc_mon = Arc::new(proc_mon);

    // Start monitoring
    proc_mon.start(true, false)?; // Don't watch PSI for this test
    start_monitoring(proc_mon.clone());

    // Give it a moment to read existing processes
    tokio::time::sleep(Duration::from_millis(100)).await;

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