use axum::serve;
use log::{error, info};
use pmond::ProcMon;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};
use ws::WSServer;

mod handlers;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    env_logger::init();

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
    start_periodic_broadcast(ws_server.clone(), proc_mon.clone());

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
fn start_periodic_broadcast(ws_server: Arc<WSServer>, proc_mon: Arc<ProcMon>) {
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(10)).await;
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
