use clap::Parser;

use echo_service;

use lmesh::LocalDiscovery;

use log::{error, info};

#[cfg(feature = "pmon")]
use pmon;
#[cfg(feature = "pmon")]
use pmon::proc::ProcMon;

use std::process;
use std::sync::Arc;

#[cfg(feature = "ssh")]
use russhd::{run_ssh_server, SshServer};

use sshmesh::ca::CA;
use sshmesh::http::{get_port_from_env, H2Server};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
enum Command {
    /// Run the mesh server
    Mesh,
    /// Run the UDS echo server
    Uds {
        /// Socket path for the UDS server
        #[arg(short, long, default_value = "/tmp/uds_echo.socket")]
        socket: std::path::PathBuf,

        /// Buffer size for read/write operations
        #[arg(short, long, default_value_t = 4096)]
        buffer_size: usize,
    },
    /// Run the UDS echo client
    UdsClient {
        /// Socket path for the UDS server
        #[arg(short, long, default_value = "/tmp/uds_echo.socket")]
        socket: std::path::PathBuf,

        /// Number of iterations for benchmarking
        #[arg(short, long, default_value_t = 100)]
        iterations: usize,

        /// Message size for benchmarking
        #[arg(short, long, default_value_t = 100)]
        message_size: usize,

        /// Run in benchmark mode
        #[arg(short, long, default_value_t = false)]
        benchmark: bool,
    },
    /// Run the PMON process monitor
    Pmon {
        /// Monitoring interval in seconds
        #[arg(short, long, default_value_t = 5)]
        interval: u64,

        /// Timeout in seconds (0 for no timeout)
        #[arg(short, long, default_value_t = 0)]
        timeout: u64,

        /// Processes to monitor
        #[arg(short, long, value_delimiter = ',')]
        processes: Vec<String>,

        /// Verbose output
        #[arg(short, long, default_value_t = false)]
        verbose: bool,
    },
    /// List existing processes
    Ps,
    /// List existing processes and watch PSI
    PsWatch,
}

/// Main mesh server. Will listen on HTTP port and provide
/// basic functionality.
///
///
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    // Note: We're not initializing env_logger since tracing_subscriber handles logging

    let command = Command::parse();

    match command {
        Command::Mesh => {
            // Initialize the logger

            // Get port numbers from environment variables or use defaults
            let http_port = get_port_from_env("HTTP_PORT", 5228);
            #[cfg(feature = "ssh")]
            let ssh_port = get_port_from_env("SSH_PORT", 5222);

            #[cfg(feature = "pmon")]
            let proc_mon: Arc<ProcMon> = match ProcMon::new() {
                Ok(pm) => Arc::new(pm),
                Err(e) => {
                    error!("Failed to create ProcMon: {}", e);
                    process::exit(1);
                }
            };

            #[cfg(feature = "pmon")]
            {
                // Set callback for new processes
                proc_mon.set_callback(|p: pmon::ProcessInfo| {
                    info!(
                        "New process: pid={}, ppid={}, comm={}",
                        p.pid, p.ppid, p.comm
                    );
                });

                // Start ProcMon monitoring
                if let Err(e) = proc_mon.listen(true) {
                    error!("Failed to enable ProcMon listening: {}", e);
                }
            }

            // if let Err(e) = proc_mon.start(true, false) {
            //     error!("Failed to start ProcMon: {}", e);
            // }

            // Create and start LocalDiscovery service
            let mut local_discovery: LocalDiscovery = match LocalDiscovery::new(None).await {
                Ok(ld) => ld,
                Err(e) => {
                    error!("Failed to create LocalDiscovery: {}", e);
                    process::exit(1);
                }
            };

            info!(
                "LocalDiscovery created with public key: {}",
                local_discovery.public_key_b64()
            );

            // Start LocalDiscovery in a separate task
            if let Err(e) = local_discovery.start().await {
                error!("Failed to start LocalDiscovery: {}", e);
                process::exit(1);
            }

            // Spawn a task to periodically announce
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                    if let Err(e) = local_discovery.announce().await {
                        error!("Failed to send announcement: {}", e);
                    }
                }
            });

            // Get base directory from environment or use home directory as default
            let base_dir = std::env::var("HOME")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));

            // Create H2Server and register the /_ps handler
            let mut h2_server = H2Server::new(http_port, base_dir.clone());

            #[cfg(feature = "pmon")]
            {
                // Register the /_ps handler
                let proc_mon_clone = Arc::clone(&proc_mon);
                h2_server.add_handler(
                    "/_ps".to_string(),
                    Arc::new(move |req| {
                        let proc_mon = Arc::clone(&proc_mon_clone);
                        Box::pin(pmon::handle_ps_request(req, proc_mon))
                    }),
                );
            }

            // Create CA and register certificate handler
            let ca = match CA::new(base_dir.clone()) {
                Ok(ca) => Arc::new(ca),
                Err(e) => {
                    error!("Failed to create CA: {}", e);
                    process::exit(1);
                }
            };

            // Register the certificate signing handler
            ca.clone().register_handler_with_server(&mut h2_server);

            println!("Starting mesh server...");

            #[cfg(feature = "ssh")]
            {
                let sshs = SshServer::new(0, None, base_dir.clone());
                let sshconfig = sshs.get_config();

                tokio::select! {
                    ssh_result = run_ssh_server(ssh_port, sshconfig, sshs) => {
                        if let Err(e) = ssh_result {
                            error!("SSH server failed: {}", e);
                        }
                    },
                }
            }
        }
        Command::Uds {
            socket,
            buffer_size,
        } => {
            // Run UDS echo server
            let args = echo_service::uds::Args {
                socket,
                buffer_size,
            };
            if let Err(e) = echo_service::uds::run_server(args) {
                eprintln!("UDS server failed: {}", e);
                process::exit(1);
            }
        }
        Command::UdsClient {
            socket,
            iterations,
            message_size,
            benchmark,
        } => {
            // Run UDS echo client
            let args = echo_service::uds_client::Args {
                socket,
                iterations,
                message_size,
                benchmark,
            };
            if let Err(e) = echo_service::uds_client::run_client(&args) {
                eprintln!("UDS client failed: {}", e);
                process::exit(1);
            }
        }
        #[cfg(feature = "pmon")]
        Command::Pmon {
            interval,
            timeout,
            processes,
            verbose,
        } => {
            // Run PMON process monitor
            // Set up Ctrl-C handler
            let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let running_clone = running.clone();

            ctrlc::set_handler(move || {
                println!("Received Ctrl-C, shutting down...");
                running_clone.store(false, std::sync::atomic::Ordering::SeqCst);
                process::exit(0);
            })
            .expect("Error setting Ctrl-C handler");

            // Run PMON process monitor
            if let Err(e) = pmon::pmon_main(interval, timeout, processes, verbose).await {
                eprintln!("PMON failed: {}", e);
                process::exit(1);
            }

            // Block the main thread until exit
            loop {
                // Sleep to avoid busy waiting
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                // Check if we should exit (though Ctrl-C handler will exit directly)
                if !running.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
            }
        }
        #[cfg(not(feature = "pmon"))]
        Command::Pmon { .. } => {
            eprintln!("PMON feature is not enabled. Please compile with --features pmon");
            process::exit(1);
        }
        #[cfg(feature = "pmon")]
        Command::Ps => {
            // Create a new ProcMon instance
            let proc_mon = ProcMon::new().expect("Failed to create ProcMon");

            // Read existing processes
            proc_mon.read_existing_processes(false);

            // Print all processes
            let processes = proc_mon.get_all_processes();
            println!("PID\tPPID\tCOMM");
            for (pid, process_info) in processes.iter() {
                println!("{}\t{}\t{}", pid, process_info.ppid, process_info.comm);
            }
        }
        #[cfg(not(feature = "pmon"))]
        Command::Ps => {
            eprintln!("PMON feature is not enabled. Please compile with --features pmon");
            process::exit(1);
        }
        #[cfg(feature = "pmon")]
        Command::PsWatch => {
            // Create a new ProcMon instance
            let proc_mon = ProcMon::new().expect("Failed to create ProcMon");

            // Read existing processes and start PSI watching
            proc_mon.read_existing_processes(true);

            // Print all processes
            let processes = proc_mon.get_all_processes();
            println!("PID\tPPID\tCOMM\tCGROUP");
            for (pid, process_info) in processes.iter() {
                let cgroup = process_info
                    .cgroup_path
                    .as_ref()
                    .map(|s: &String| s.as_str())
                    .unwrap_or("None");
                println!(
                    "{}\t{}\t{}\t{}",
                    pid, process_info.ppid, process_info.comm, cgroup
                );
            }

            println!("Monitoring PSI pressure events. Press Ctrl+C to stop.");

            // Set up Ctrl-C handler
            let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let running_clone = running.clone();

            ctrlc::set_handler(move || {
                println!("Received Ctrl-C, shutting down...");
                running_clone.store(false, std::sync::atomic::Ordering::SeqCst);
                process::exit(0);
            })
            .expect("Error setting Ctrl-C handler");

            // Keep the main thread alive while monitoring
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        #[cfg(not(feature = "pmon"))]
        Command::PsWatch => {
            eprintln!("PMON feature is not enabled. Please compile with --features pmon");
            process::exit(1);
        }
    }
}
