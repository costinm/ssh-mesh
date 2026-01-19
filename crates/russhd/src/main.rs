use anyhow::Error;
use log::{error, info};
//use pmond::ProcMon;
use russhd::{get_port_from_env, handlers, run_ssh_server, AppState, SshServer};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use ws::WSServer;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Get SSH port from environment variable or use default
    let ssh_port = get_port_from_env("SSH_PORT", 2223);
    let http_port = get_port_from_env("HTTP_PORT", 8081);

    // Get base directory from environment or use home directory as default
    let base_dir = env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));

    info!(
        "Starting SSH server on port {} and HTTP server on port {} with base directory: {:?}",
        ssh_port, http_port, base_dir
    );

    // Create SSH server instance
    let ssh_server = Arc::new(SshServer::new(0, None, base_dir));

    // Create ProcMon instance
    //let proc_mon = Arc::new(ProcMon::new()?);
    //proc_mon.listen(true)?;
    /////XXXX proc_mon.start(true, true)?;

    // Create WebSocket server instance
    let ws_server = Arc::new(WSServer::new());

    // Create AppState
    let app_state = AppState {
        ssh_server: ssh_server.clone(),
        //proc_mon: proc_mon.clone(),
        ws_server: ws_server.clone(),
    };

    // Start SSH server in a separate task
    let ssh_server_clone = ssh_server.clone();
    let ssh_server_task = tokio::spawn(async move {
        let config = ssh_server_clone.get_config();
        if let Err(e) = run_ssh_server(ssh_port, config, (*ssh_server_clone).clone()).await {
            error!("SSH server failed: {}", e);
        }
    });

    // Create Axum app
    let app = handlers::app(app_state);

    // Start Axum server
    let http_addr = format!("0.0.0.0:{}", http_port);
    let listener = TcpListener::bind(&http_addr).await?;
    info!("Listening on http://{}", http_addr);
    axum::serve(listener, app.into_make_service()).await?;

    // Wait for SSH server to finish
    ssh_server_task.await?;

    Ok(())
}
