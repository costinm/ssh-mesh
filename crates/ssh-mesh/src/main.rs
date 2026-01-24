use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use ws::WSServer;




use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

/// Initialize telemetry with JSON tracing and Perfetto tracing.
///
/// Configuration is controlled via the `RUST_LOG` environment variable.
/// Examples:
/// - `RUST_LOG=info` -> Log info and above
/// - `RUST_LOG=debug` -> Log debug and above
/// - `RUST_LOG=ssh_mesh=debug,info` -> Log debug for ssh_mesh crate, info for others
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


fn get_local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    init_telemetry();

    let main_span = tracing::info_span!("main");
    let _main_guard = main_span.enter();

    // Import required items that were replaced by the block
    use log::{error, info};
    use ssh_mesh::{get_port_from_env, handlers, run_ssh_server, AppState, SshServer};

    let host_ip = get_local_ip().unwrap_or_else(|| "unknown".to_string());
    info!("Starting ssh-mesh on host: {}", host_ip);

    // Get SSH port from environment variable or use default
    let ssh_port = get_port_from_env("SSH_PORT", 15022);
    let http_port = get_port_from_env("HTTP_PORT", 15028);

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
