use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tracing::{error, info};
use ws::WSServer;
use axum::serve;




use pmond::{ProcMon, proc_netlink};

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
    let json_layer = tracing_subscriber::fmt::layer()
        .json();

    let perfetto_layer = std::env::var("PERFETTO_TRACE").ok().map(|file| {
        tracing_perfetto::PerfettoLayer::new(std::sync::Mutex::new(
            std::fs::File::create(file).expect("failed to create trace file")
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

    // Default server mode
    run_server(args.refresh).await?;

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
                proc_netlink::NetlinkEvent::Fork { parent_tgid, child_pid, child_tgid, .. } => {
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

    pmond::mcp::run_stdio_server(proc_mon).await
}

async fn run_server(refresh: u64) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting PMON process monitor");

    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;
    let proc_mon = Arc::new(proc_mon);

    // Start monitoring
    proc_mon.start(true, true)?;
    start_monitoring(proc_mon.clone());

    info!("PMON process monitor started successfully");

    // Create a new WebSocket server
    let ws_server = Arc::new(WSServer::new());

    // Start the periodic broadcast task
    start_periodic_broadcast(ws_server.clone(), proc_mon.clone(), refresh);

    // Set up HTTP server
    let addr = "127.0.0.1:8081";
    let listener = TcpListener::bind(addr).await?;
    info!("Listening on http://{}", addr);

    // Create the Axum app
    let app = pmond::handlers::app(proc_mon, ws_server);

    // Run the server
    serve(listener, app.into_make_service()).await?;

    Ok(())
}

/// Periodically broadcasts the process list to all connected clients.
fn start_periodic_broadcast(ws_server: Arc<WSServer>, proc_mon: Arc<ProcMon>, refresh: u64) {
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(refresh)).await;
            let processes = proc_mon.get_all_processes();
            match serde_json::to_string(&processes) {
                Ok(json) => {
                    if let Err(e) = ws_server.broadcast_message(&json).await {
                        error!("Failed to broadcast process list: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to serialize process list: {}", e);
                }
            }
        }
    });
}

#[cfg(test)]
mod telemetry_test;
