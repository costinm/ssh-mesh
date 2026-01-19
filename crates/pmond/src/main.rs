use axum::serve;
use clap::Parser;
use log::{error, info};
use pmond::ProcMon;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};
use ws::WSServer;

mod handlers;

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

    /// Refresh interval in seconds for server mode (default: 10)
    #[clap(long = "refresh", default_value = "10", value_name = "SECONDS")]
    refresh: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    env_logger::init();

    let args = Args::parse();

    if args.ps {
        show_processes()?;
        return Ok(());
    }

    if let Some(pid) = args.watch {
        watch_process(pid, args.refresh).await?;
        return Ok(());
    }

    // Default server mode
    run_server(args.refresh).await?;

    Ok(())
}

fn show_processes() -> Result<(), Box<dyn std::error::Error>> {
    info!("Showing processes");

    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;

    // Enable listening for events
    proc_mon.listen(true)?;

    // Wrap the monitor in an Arc for shared ownership
    let proc_mon = Arc::new(proc_mon);

    // Start monitoring in a background thread
    proc_mon.start(true, true)?;

    // Get processes and display them sorted by RSS
    let processes = proc_mon.get_all_processes();
    let mut processes_list: Vec<(&u32, &pmond::ProcessInfo)> = processes.iter().collect();
    processes_list.sort_by_key(|(_, p)| p.mem_info.as_ref().map(|m| m.anon).unwrap_or(0));

    for (_, process) in processes_list.iter().rev() {
        println!(
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

    // Enable listening for events
    proc_mon.listen(true)?;

    // Wrap the monitor in an Arc for shared ownership
    let proc_mon = Arc::new(proc_mon);

    // Start monitoring in a background thread
    proc_mon.start(true, true)?;

    println!(
        "Watching process {} with refresh interval {}s",
        pid, refresh
    );
    println!("Press Ctrl+C to stop");

    // Watch for updates for the specific process
    let refresh_duration = Duration::from_secs(refresh);
    loop {
        sleep(refresh_duration).await;

        // Get processes and find the specific one
        let processes = proc_mon.get_all_processes();
        if let Some(process) = processes.get(&pid) {
            if let Some(mem_info) = &process.mem_info {
                println!(
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

async fn run_server(refresh: u64) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting PMON process monitor");

    // Create a new ProcMon instance
    let proc_mon = ProcMon::new()?;

    // Enable listening for events
    proc_mon.listen(true)?;

    // Wrap the monitor in an Arc for shared ownership
    let proc_mon = Arc::new(proc_mon);

    // Start monitoring in a background thread
    proc_mon.start(true, true)?;

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
    let app = handlers::app(proc_mon, ws_server);

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
