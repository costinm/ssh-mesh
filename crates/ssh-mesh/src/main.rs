use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use ws::WSServer;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry, reload};

/// Initialize telemetry with dynamic reload support and in-memory log buffering.
///
/// Configuration is controlled via the `RUST_LOG` environment variable.
/// Examples:
/// - `RUST_LOG=info` -> Log info and above
/// - `RUST_LOG=debug` -> Log debug and above
/// - `RUST_LOG=ssh_mesh=debug,info` -> Log debug for ssh_mesh crate, info for others
///
/// The tracing level can be dynamically changed at runtime using the reload handle.
/// All log events are also captured in the provided log buffer for viewing via WebSocket.
fn init_telemetry(log_buffer: ssh_mesh::local_trace::LogBuffer) {
    let filter = EnvFilter::from_default_env();
    let (filter, reload_handle) = reload::Layer::new(filter);
    let fmt_layer = tracing_subscriber::fmt::layer().compact();
    let buffer_layer = ssh_mesh::local_trace::LogBufferLayer::new(log_buffer);

    Registry::default()
        .with(filter)
        .with(fmt_layer)
        .with(buffer_layer)
        .init();

    // Store the reload handle globally
    let _ = ssh_mesh::TRACING_RELOAD_HANDLE.set(reload_handle);

    tracing::trace!(hello = "world", foo = 2, "Test {}", 1);
}

fn get_local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

/// Function to get port from environment variable or use default
fn get_port_from_env(var_name: &str, default: u16) -> u16 {
    std::env::var(var_name)
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Create log buffer early so we can initialize telemetry with it
    let log_buffer = ssh_mesh::local_trace::create_log_buffer();

    init_telemetry(log_buffer.clone());

    // Import required items
    use log::{error, info};
    use ssh_mesh::{AppState, ExecConfig, SshServer, handlers, run_ssh_server};

    let host_ip = get_local_ip().unwrap_or_else(|| "unknown".to_string());

    // Get SSH port from environment variable or use default
    let ssh_port = get_port_from_env("SSH_PORT", 15022);
    let http_port = get_port_from_env("HTTP_PORT", 0);
    let https_port = get_port_from_env("HTTPS_PORT", 15028);
    // Start SOCKS5 server if SOCKS_PORT is set
    let socks_port = get_port_from_env("SOCKS_PORT", 0);

    // Get base directory from environment variable SSH_BASEDIR
    // If not set, use $HOME/.ssh or /tmp/.ssh as default
    let base_dir = env::var("SSH_BASEDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let mut path = env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/tmp"));
            path.push(".ssh");
            path
        });

    let sftp_server_path = env::var("SFTP_SERVER_PATH").ok();
    let sftp_root = env::var("SFTP_ROOT").ok().map(PathBuf::from);

    // Create SSH server instance
    let ssh_server = Arc::new(SshServer::new(0, None, base_dir.clone(), sftp_server_path, sftp_root));

    // Create WebSocket server instance
    let ws_server = Arc::new(WSServer::new());

    // Initialize ProcMon if enabled
    #[cfg(feature = "pmon")]
    let proc_mon = {
        let pm = Arc::new(pmond::ProcMon::new().expect("Failed to create ProcMon"));
        // Start monitoring: read_sync=true, watch_psi=true, event_tx=None
        if let Err(e) = pm.start(true, true, None) {
            error!("Failed to start ProcMon: {}", e);
        } else {
            info!("ProcMon started successfully");
        }
        pm
    };

    // Create AppState

    let app_state = AppState {
        ssh_server: ssh_server.clone(),
        ws_server: ws_server.clone(),
        target_http_address: std::env::var("APP_HTTP_PORT").ok(),
        log_buffer: log_buffer.clone(),
        ssh_client_manager: Arc::new(ssh_mesh::sshc::SshClientManager::new(
            ssh_server.private_key().clone(),
            (*ssh_server.ca_keys).clone(),
            {
                // Default: base_dir/config (i.e. ~/.ssh/config).
                // Override with SSH_CONFIG env var.
                let config_path = env::var("SSH_CONFIG")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| base_dir.join("config"));
                if config_path.exists() {
                    Some(config_path)
                } else {
                    None
                }
            },
            env::var("MUX_DIR").ok().map(PathBuf::from),
        )),
    };

    info!(
        "Starting SSH_PORT {} and HTTPS_PORT={} HTTP_PORT={} SSH_BASEDIR={:?} app_port={:?} ip={}",
        ssh_port, https_port, http_port, base_dir, &app_state.target_http_address, host_ip
    );

    // Start SSH server in a separate task
    let ssh_server_clone = ssh_server.clone();
    let _ssh_server_task = tokio::spawn(async move {
        let config = ssh_server_clone.get_config();
        if let Err(e) = run_ssh_server(ssh_port, config, (*ssh_server_clone).clone()).await {
            error!("SSH server failed: {}", e);
        }
    });

    if socks_port > 0 {
        let socks_addr = format!("0.0.0.0:{}", socks_port);
        tokio::spawn(async move {
            match ssh_mesh::socks5::Socks5Server::bind(&socks_addr).await {
                Ok(server) => {
                    info!("SOCKS5 server listening on {}", socks_addr);
                    server.run().await;
                }
                Err(e) => {
                    error!("Failed to start SOCKS5 server: {}", e);
                }
            }
        });
    }

    // Create Axum app
    let mut app = handlers::app(app_state.clone());

    app = app.nest_service("/", pmond::handlers::app(proc_mon.clone()));

    // HTTPS server - WIP, authz and authn not implemented.
    if https_port > 0 {
        let cert_path = base_dir.join("id_ecdsa.crt");
        let key_path = base_dir.join("id_ecdsa");
        if cert_path.exists() && key_path.exists() {
            let app = app.clone();
            let https_addr = format!("0.0.0.0:{}", https_port);
            match ssh_mesh::auth::TlsServer::new(&cert_path, &key_path, None, &https_addr) {
                Ok(tls_server) => {
                    info!("Starting HTTPS server on https://{}", https_addr);
                    tokio::spawn(async move {
                        if let Err(e) = ssh_mesh::auth::run_axum_https_server(
                            https_port,
                            tls_server.acceptor,
                            app,
                        )
                        .await
                        {
                            error!("HTTPS server failed: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to initialize TLS config: {}", e);
                }
            }
        }
    }

    // HTTP server - forwards to the app's port, with handlers for
    // ssh tunneling and an admin interface.
    // TODO: separate admin interface to different port.
    if http_port > 0 {
        let http_addr = format!("0.0.0.0:{}", http_port);
        let listener = TcpListener::bind(&http_addr).await?;
        // Run HTTP server in background
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app.into_make_service()).await {
                error!("HTTP server failed: {}", e);
            }
        });
    }

    // Check for command line arguments (excluding $0)
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        // Run the command in foreground
        let exec_user = env::var("EXEC_USER").unwrap_or_else(|_| "1000".to_string());
        let uid: u32 = exec_user.parse().expect("Invalid EXEC_USER");

        ssh_mesh::run_exec_command(ExecConfig {
            args: args[1..].to_vec(),
            uid,
        })?;
    } else {
        // Daemon mode — wait for shutdown signal.
        // Handle both SIGINT (ctrl-c) and SIGTERM for graceful shutdown.
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Received SIGINT (ctrl-c), shutting down");
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, shutting down");
                }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await?;
            info!("Received ctrl-c, shutting down");
        }
    }

    info!("Exiting");
    std::process::exit(0);
}
