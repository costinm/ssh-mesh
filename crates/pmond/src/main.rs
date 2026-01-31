use axum::serve;
use clap::Parser;
use pmond::{proc_netlink, psi::PsiWatcher, ProcMon};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{broadcast, mpsc};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info};

fn get_local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

#[derive(Parser, Debug)]
#[clap(name = "pmond", version = "0.1.0", author = "Author")]
struct Args {
    /// Run server mode
    #[clap(long = "server")]
    server: bool,

    /// Show processes only (no server)
    #[clap(long = "ps")]
    ps: bool,

    /// Watch a specific process ID
    #[clap(long = "watch", value_name = "PID")]
    watch: Option<u32>,

    /// Run in MCP (Model Context Protocol) mode via stdin
    #[clap(long = "mcp")]
    mcp: bool,

    /// Refresh interval in seconds for server mode (default: 10)
    #[clap(long = "refresh", default_value = "10", value_name = "SECONDS")]
    refresh: u64,

    /// Run MCP via UDS at the specified path
    #[clap(long = "mcp-uds", value_name = "PATH")]
    mcp_uds: Option<String>,

    /// Start monitoring processes via netlink
    #[clap(long = "monitor")]
    monitor: bool,

    /// Show debug information
    #[clap(long = "debug")]
    debug: bool,
}

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

/// Initialize telemetry with JSON tracing and Perfetto tracing.
///
/// Configuration is controlled via the `RUST_LOG` environment variable.
/// Examples:
/// - `RUST_LOG=info` -> Log info and above
/// - `RUST_LOG=debug` -> Log debug and above
/// - `RUST_LOG=pmond=debug,info` -> Log debug for pmond crate, info for others
fn init_telemetry() {
    let out_layer = tracing_subscriber::fmt::layer().compact();

    let perfetto_layer = std::env::var("PERFETTO_TRACE").ok().map(|file| {
        tracing_perfetto::PerfettoLayer::new(std::sync::Mutex::new(
            std::fs::File::create(file).expect("failed to create trace file"),
        ))
    });

    Registry::default()
        .with(EnvFilter::from_default_env())
        .with(out_layer)
        .with(perfetto_layer)
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_telemetry();

    let main_span = tracing::info_span!("pmond");
    let _main_guard = main_span.enter();

    let host_ip = get_local_ip().unwrap_or_else(|| "unknown".to_string());
    info!("Starting pmond on host: {}", host_ip);

    let args = Args::parse();

    if args.ps {
        show_processes()?;
        return Ok(());
    }

    if let Some(pid) = args.watch {
        watch_process(pid, args.refresh).await?;
        return Ok(());
    }

    if args.mcp {
        run_mcp_server().await?;
        return Ok(());
    }

    if args.monitor {
        run_monitor(args.debug, args.mcp_uds).await?;
        return Ok(());
    }

    // Authorized UID for MCP UDS
    let auth_uid = std::env::var("MCP_AUTHORIZED_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());

    // Default server mode
    run_server(args.refresh, args.mcp_uds, auth_uid).await?;

    Ok(())
}

async fn run_monitor(
    debug: bool,
    mcp_uds: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting PMON monitor mode");

    let proc_mon = ProcMon::new()?;
    let proc_mon = Arc::new(proc_mon);

    let (tx, rx) = mpsc::channel(100);

    // Start monitoring (periodic snapshot and PSI)
    proc_mon.start(true, true, Some(tx.clone()))?;

    let (event_tx, _) = broadcast::channel::<serde_json::Value>(1024);

    // Start monitoring consumer loop
    start_monitoring(
        proc_mon.psi_watcher.clone(),
        tx,
        rx,
        Some(event_tx.clone()),
        debug,
    );

    // Determine path for pwatch.sock
    let path_str = if let Some(path) = mcp_uds {
        if path.ends_with(".mcp") || path.ends_with(".sock") || path.ends_with(".http") {
            let base = path.rsplit_once('.').map(|x| x.0).unwrap_or(&path);
            format!("{}.pwatch", base)
        } else {
            format!("{}/pwatch.sock", path)
        }
    } else {
        let uid = unsafe { libc::getuid() };
        format!("/run/user/{}/pwatch.sock", uid)
    };

    // Ensure parent directory exists
    let path = std::path::Path::new(&path_str);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(path);

    let listener = UnixListener::bind(path)?;
    info!("Mirroring events to UDS: {}", path_str);

    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let mut rx = event_tx.subscribe();
                tokio::spawn(async move {
                    while let Ok(msg) = rx.recv().await {
                        let json = serde_json::to_vec(&msg).unwrap();
                        if let Err(_) = stream.write_all(&json).await {
                            break;
                        }
                        if let Err(_) = stream.write_all(b"\n").await {
                            break;
                        }
                    }
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

fn start_monitoring(
    psi_watcher: Arc<PsiWatcher>,
    tx: mpsc::Sender<pmond::MonitoringEvent>,
    mut rx: mpsc::Receiver<pmond::MonitoringEvent>,
    event_tx: Option<broadcast::Sender<serde_json::Value>>,
    debug: bool,
) -> tokio::task::JoinHandle<()> {
    let running = psi_watcher.running.clone();

    // Start netlink listener
    tokio::task::spawn_blocking(move || {
        if let Err(e) = proc_netlink::run_netlink_listener(tx, running) {
            error!("Netlink listener error: {}", e);
        }
    });

    // Start event consumer
    let pw = psi_watcher.clone();
    tokio::spawn(async move {
        while let Some(monitoring_event) = rx.recv().await {
            let mut should_broadcast = true;
            let event_json = match monitoring_event {
                pmond::MonitoringEvent::Netlink(event) => match event {
                    proc_netlink::NetlinkEvent::Fork {
                        parent_pid,
                        parent_tgid,
                        child_pid,
                        child_tgid,
                    } => {
                        let p_pid = if parent_tgid != 0 {
                            parent_tgid
                        } else {
                            parent_pid
                        };
                        let c_pid = if child_tgid != 0 {
                            child_tgid
                        } else {
                            child_pid
                        };

                        pw.handle_fork(p_pid, child_pid, c_pid);
                        should_broadcast = false;
                        debug!(
                            "fork: parent pid={} -> child pid={} tgid={}",
                            p_pid, child_pid, c_pid
                        );
                        json!({
                            "type": "fork",
                            "parent_pid": p_pid,
                            "comm": pmond::read_comm(p_pid),
                            "child_pid": child_pid,
                            "child_tgid": c_pid,
                        })
                    }
                    proc_netlink::NetlinkEvent::Exec {
                        process_pid,
                        process_tgid,
                    } => {
                        let pid = if process_tgid != 0 {
                            process_tgid
                        } else {
                            process_pid
                        };
                        pw.handle_exec(process_pid, pid);

                        let mut comm = pmond::read_comm(pid);
                        let mut cmdline = pmond::read_cmdline(pid);
                        let mut exe = pmond::read_exe(pid);
                        let mut cgroup = pmond::read_cgroup_path(pid);

                        // Fallback to process_pid if tgid fields were null
                        if (cmdline.is_none() || exe.is_none())
                            && process_pid != pid
                            && process_pid != 0
                        {
                            if cmdline.is_none() {
                                cmdline = pmond::read_cmdline(process_pid);
                            }
                            if exe.is_none() {
                                exe = pmond::read_exe(process_pid);
                            }
                            if cgroup.is_none() {
                                cgroup = pmond::read_cgroup_path(process_pid);
                            }
                            if comm == "(unknown)" {
                                comm = pmond::read_comm(process_pid);
                            }
                        }

                        json!({
                            "type": "exec",
                            "pid": process_pid,
                            "tgid": process_tgid,
                            "comm": comm,
                            "cmdline": cmdline,
                            "exe": exe,
                            "cgroup": cgroup,
                        })
                    }
                    proc_netlink::NetlinkEvent::Exit {
                        process_tgid,
                        process_pid,
                        exit_code,
                        exit_signal,
                        ..
                    } => {
                        let pid = if process_tgid != 0 {
                            process_tgid
                        } else {
                            process_pid
                        };
                        pw.handle_exit(pid);
                        json!({
                            "type": "exit",
                            "pid": process_pid,
                            "tgid": process_tgid,
                            "exit_code": exit_code,
                            "exit_signal": exit_signal
                        })
                    }
                    proc_netlink::NetlinkEvent::Uid {
                        process_pid,
                        process_tgid,
                        ruid,
                        euid,
                    } => {
                        let pid = if process_tgid != 0 {
                            process_tgid
                        } else {
                            process_pid
                        };
                        pw.handle_uid(process_pid, pid, ruid, euid);
                        should_broadcast = false;
                        debug!(
                            "uid change: pid={} tgid={} ruid={} euid={}",
                            process_pid, pid, ruid, euid
                        );
                        json!({
                            "type": "uid",
                            "pid": process_pid,
                            "tgid": process_tgid,
                            "ruid": ruid,
                            "euid": euid,
                            "comm": pmond::read_comm(pid)
                        })
                    }
                    proc_netlink::NetlinkEvent::Comm {
                        process_pid,
                        process_tgid,
                        comm,
                    } => {
                        let pid = if process_tgid != 0 {
                            process_tgid
                        } else {
                            process_pid
                        };
                        pw.handle_comm(process_pid, pid, comm.clone());
                        json!({
                            "type": "comm",
                            "pid": process_pid,
                            "tgid": process_tgid,
                            "comm": comm
                        })
                    }
                },
                pmond::MonitoringEvent::Pressure(event) => {
                    json!({
                        "type": "pressure",
                        "pid": event.pid,
                        "pressure_type": format!("{:?}", event.pressure_type).to_lowercase(),
                        "data": event.pressure_data,
                        "comm": pmond::read_comm(event.pid)
                    })
                }
            };

            if should_broadcast {
                if debug {
                    println!("{}", serde_json::to_string(&event_json).unwrap());
                }

                if let Some(ref tx) = event_tx {
                    let _ = tx.send(event_json);
                }
            }
        }
    })
}

fn show_processes() -> Result<(), Box<dyn std::error::Error>> {
    info!("Showing processes");

    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;
    let proc_mon = Arc::new(proc_mon);

    // Start monitoring
    proc_mon.start(true, true, None)?;

    // Get processes and display them sorted by RSS
    let processes = proc_mon.get_all_processes();
    let mut processes_list: Vec<(&u32, &pmond::ProcessInfo)> = processes.iter().collect();
    processes_list.sort_by_key(|(_, p)| p.mem_info.as_ref().map(|m| m.anon).unwrap_or(0));

    for (_, process) in processes_list.iter().rev() {
        info!(
            "PID: {} | RSS: {} | Name: {}",
            process.pid,
            process.mem_info.as_ref().map(|m| m.anon).unwrap_or(0),
            &process.comm
        );
    }

    Ok(())
}

async fn watch_process(pid: u32, refresh: u64) -> Result<(), Box<dyn std::error::Error>> {
    info!("Watching process with PID: {}", pid);

    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;
    let proc_mon = Arc::new(proc_mon);

    // Start monitoring
    proc_mon.start(true, true, None)?;

    info!(
        "Watching process {} with refresh interval {}s",
        pid, refresh
    );
    info!("Press Ctrl+C to stop");

    // Watch for updates for the specific process
    let refresh_duration = Duration::from_secs(refresh);
    loop {
        sleep(refresh_duration).await;

        // Get processes and find the specific one
        let processes = proc_mon.get_all_processes();
        if let Some(process) = processes.get(&pid) {
            if let Some(mem_info) = &process.mem_info {
                info!(
                    "Anon: {} | File: {} | Kernel: {} | Shmem: {} | Swapcached: {}",
                    mem_info.anon,
                    mem_info.file,
                    mem_info.kernel,
                    mem_info.shmem,
                    mem_info.swapcached
                );
            }
        }
    }
}

async fn run_mcp_server() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting PMON MCP server");

    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;
    let proc_mon = Arc::new(proc_mon);

    // MCP server might start monitoring internally or we start it here
    proc_mon.start(true, true, None)?;

    pmond::handlers::run_stdio_server(proc_mon).await
}

async fn run_server(
    _refresh: u64,
    mcp_uds: Option<String>,
    auth_uid: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting PMON process monitor");

    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;
    let proc_mon = Arc::new(proc_mon);

    let (tx, rx) = mpsc::channel(100);

    // Start monitoring
    proc_mon.start(true, true, Some(tx.clone()))?;
    start_monitoring(proc_mon.psi_watcher.clone(), tx, rx, None, false);

    info!("PMON process monitor started successfully");

    // Start UDS servers
    let path_str = if let Some(path) = mcp_uds {
        path
    } else {
        // Default to /run/user/<uid>/pmond.sock
        let uid = unsafe { libc::getuid() };
        format!("/run/user/{}/pmond.sock", uid)
    };

    // Ensure parent directory exists
    let path = PathBuf::from(&path_str);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let http_path = format!("{}.http", path_str);
    let mcp_path = format!("{}.mcp", path_str);

    let pm_http = proc_mon.clone();
    tokio::spawn(async move {
        if let Err(e) = pmond::handlers::run_uds_http_server(pm_http, &http_path, auth_uid).await {
            error!("UDS HTTP server error: {}", e);
        }
    });

    let pm_mcp = proc_mon.clone();
    tokio::spawn(async move {
        if let Err(e) = pmond::handlers::run_uds_mcp_server(pm_mcp, &mcp_path, auth_uid).await {
            error!("UDS MCP server error: {}", e);
        }
    });

    // Set up HTTP server
    let addr = "127.0.0.1:8081";
    let listener = TcpListener::bind(addr).await?;
    info!("Listening on http://{}", addr);

    // Create the Axum app
    let app = pmond::handlers::app(proc_mon);

    // Run the server
    serve(listener, app.into_make_service()).await?;

    Ok(())
}
