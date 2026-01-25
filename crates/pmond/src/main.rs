use axum::serve;
use clap::Parser;
use pmond::{proc_netlink, ProcMon};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tracing::{error, info};

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
    let json_layer = tracing_subscriber::fmt::layer().json();

    let perfetto_layer = std::env::var("PERFETTO_TRACE").ok().map(|file| {
        tracing_perfetto::PerfettoLayer::new(std::sync::Mutex::new(
            std::fs::File::create(file).expect("failed to create trace file"),
        ))
    });

    Registry::default()
        .with(EnvFilter::from_default_env())
        .with(json_layer)
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

    // Authorized UID for MCP UDS
    let auth_uid = std::env::var("MCP_AUTHORIZED_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());

    // Default server mode
    run_server(args.refresh, args.mcp_uds, auth_uid).await?;

    Ok(())
}

fn start_monitoring(proc_mon: Arc<ProcMon>) -> tokio::task::JoinHandle<()> {
    let (tx, mut rx) = mpsc::channel(100);
    let running = proc_mon.running.clone();

    // Start netlink listener
    tokio::task::spawn_blocking(move || {
        if let Err(e) = proc_netlink::run_netlink_listener(tx, running) {
            error!("Netlink listener error: {}", e);
        }
    });

    // Start event consumer
    let pm = proc_mon.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                proc_netlink::NetlinkEvent::Fork {
                    parent_tgid,
                    child_pid,
                    child_tgid,
                    ..
                } => {
                    pm.handle_fork(parent_tgid, child_pid, child_tgid);
                }
                proc_netlink::NetlinkEvent::Exit { process_tgid, .. } => {
                    pm.handle_exit(process_tgid);
                }
                _ => {}
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
    proc_mon.start(true, true)?;
    start_monitoring(proc_mon.clone());

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
    proc_mon.start(true, true)?;
    start_monitoring(proc_mon.clone());

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
    proc_mon.start(true, true)?;
    start_monitoring(proc_mon.clone());

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

    // Start monitoring
    proc_mon.start(true, true)?;
    start_monitoring(proc_mon.clone());

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
