use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
#[cfg(feature = "ws")]
use ws::WSServer;

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
    let (log_buffer, _trace_guard) = mesh::local_trace::init("ssh-mesh");
    mesh::local_trace::serve("ssh-mesh", log_buffer);

    // Import required items
    use log::{error, info};
    use ssh_mesh::{AppState, ExecConfig, MeshNode, MeshNodeConfig, handlers, run_ssh_server};

    let app_paths = mesh::paths::AppPaths::for_app("ssh-mesh");
    let host_ip = get_local_ip().unwrap_or_else(|| "unknown".to_string());

    // Get SSH port from environment variable or use default
    let ssh_port = get_port_from_env("SSH_PORT", 15022);
    let http_port = get_port_from_env("HTTP_PORT", 15080);
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

    // Ensure base directory exists
    let _ = std::fs::create_dir_all(&base_dir);

    // Create config from env vars, layering: defaults → config file → env vars
    let cfg: MeshNodeConfig = {
        let mut builder = config::Config::builder()
            .set_default("ssh_port", ssh_port as i64)
            .unwrap()
            .set_default("sftp_server_path", env::var("SFTP_SERVER_PATH").ok())
            .unwrap()
            .set_default("sftp_root", env::var("SFTP_ROOT").ok())
            .unwrap();

        let config_dir = env::var("SSH_MESH_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| app_paths.etc.clone());

        // Layer config file from config_dir (mesh.yaml, mesh.json, mesh.toml)
        for ext in &["yaml", "json", "toml"] {
            let path = config_dir.join(format!("mesh.{}", ext));
            if path.exists() {
                builder = builder.add_source(config::File::from(path));
                break;
            }
        }

        // Layer env overrides
        if http_port > 0 {
            builder = builder.set_override("http_port", http_port as i64).unwrap();
        }

        match builder.build().and_then(|c| c.try_deserialize()) {
            Ok(mut c) => {
                let c: &mut MeshNodeConfig = &mut c;
                c.base_dir = Some(base_dir.clone());
                c.config_dir = Some(config_dir.clone());
                c.ssh_port = Some(ssh_port);
                c.clone()
            }
            Err(e) => {
                log::warn!("Failed to load config via config-rs, using defaults: {}", e);
                MeshNodeConfig {
                    base_dir: Some(base_dir.clone()),
                    config_dir: Some(config_dir.clone()),
                    ssh_port: Some(ssh_port),
                    http_port: if http_port > 0 { Some(http_port) } else { None },
                    sftp_server_path: env::var("SFTP_SERVER_PATH").ok(),
                    sftp_root: env::var("SFTP_ROOT").ok().map(PathBuf::from),
                    ..Default::default()
                }
            }
        }
    };

    // Create MeshNode instance
    let ssh_server = Arc::new(MeshNode::new(Some(base_dir.clone()), Some(cfg)));

    if env::var("SSH_MESH_TRUSTED_STDIO")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        info!("Starting trusted SSH transport on stdin/stdout");
        ssh_mesh::trusted_transport::run_trusted_server_stdio((*ssh_server).clone()).await?;
        return Ok(());
    }

    let trusted_uds_path = env::var("SSH_MESH_TRUSTED_UDS_PATH")
        .ok()
        .map(PathBuf::from)
        .or_else(|| ssh_server.cfg.trusted_uds_path.clone());
    if let Some(uds_path) = trusted_uds_path {
        let trusted_server = ssh_server.clone();
        tokio::spawn(async move {
            if let Err(e) = ssh_mesh::trusted_transport::run_trusted_uds_server(
                (*trusted_server).clone(),
                uds_path,
            )
            .await
            {
                error!("trusted UDS SSH server failed: {}", e);
            }
        });
    }

    let trusted_vsock_port = env::var("SSH_MESH_VSOCK_PORT")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .or(ssh_server.cfg.trusted_vsock_port);
    if let Some(vsock_port) = trusted_vsock_port {
        #[cfg(target_os = "linux")]
        {
            let vsock_cid = env::var("SSH_MESH_VSOCK_CID")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .or(ssh_server.cfg.trusted_vsock_cid)
                .unwrap_or(ssh_mesh::trusted_transport::VMADDR_CID_ANY);
            let trusted_server = ssh_server.clone();
            tokio::spawn(async move {
                if let Err(e) = ssh_mesh::trusted_transport::run_trusted_vsock_server(
                    (*trusted_server).clone(),
                    vsock_cid,
                    vsock_port,
                )
                .await
                {
                    error!("trusted vsock SSH server failed: {}", e);
                }
            });
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = vsock_port;
            error!("SSH_MESH_VSOCK_PORT is set, but virtio-vsock is only supported on Linux");
        }
    }

    // Create WebSocket server instance
    #[cfg(feature = "ws")]
    let ws_server = Arc::new(WSServer::new());

    // Create AppState

    let user_certificate_path = base_dir.join("id_ecdsa-user-cert.pub");
    let user_certificate = if user_certificate_path.exists() {
        match russh::keys::load_openssh_certificate(&user_certificate_path) {
            Ok(cert) => Some(cert),
            Err(e) => {
                error!(
                    "Failed to load user certificate {}: {}",
                    user_certificate_path.display(),
                    e
                );
                None
            }
        }
    } else {
        None
    };

    let app_state = AppState {
        ssh_server: ssh_server.clone(),
        target_http_address: std::env::var("APP_HTTP_PORT").ok(),
        ssh_client_manager: Arc::new(
            ssh_mesh::sshc::SshClientManager::new_with_certificate(
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
                env::var("SSH_MUX").ok().map(PathBuf::from),
                user_certificate,
            )
            .with_discovery_dir(Some(base_dir.clone())),
        ),
    };

    // Start configured SSH client connections from config
    let configured_clients = ssh_server.cfg.clients.clone();
    if !configured_clients.is_empty() {
        info!(
            "Starting {} configured SSH client connections",
            configured_clients.len()
        );
        let manager_clone = app_state.ssh_client_manager.clone();
        tokio::spawn(async move {
            ssh_mesh::sshc::start_configured_clients(manager_clone, configured_clients).await;
        });
    }

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
        let socks_addr = format!("127.0.0.1:{}", socks_port);
        tokio::spawn(async move {
            match ssh_mesh::socks5::Socks5Server::bind_with_config(
                &socks_addr,
                ssh_mesh::socks5::Socks5Config::default(),
            )
            .await
            {
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
    #[cfg(feature = "ws")]
    let mut app = handlers::app(app_state.clone());
    #[cfg(not(feature = "ws"))]
    let app = handlers::app(app_state.clone());

    #[cfg(feature = "ws")]
    {
        let ws_handlers: Vec<(String, Arc<dyn mesh::StreamHandler>)> = vec![
            (
                "/_m/_ws/_ssh".to_string(),
                Arc::new(handlers::SshWsHandler {
                    ssh_server: app_state.ssh_server.clone(),
                }),
            ),
            (
                "/_m/_ws/_tcp/*path".to_string(),
                Arc::new(handlers::TcpProxyWsHandler),
            ),
            (
                "/_m/_ws/_uds/*path".to_string(),
                Arc::new(handlers::UdsProxyWsHandler),
            ),
            (
                "/_m/_ws/_exec/*cmd".to_string(),
                Arc::new(handlers::ExecWsHandler),
            ),
        ];

        let ws_state = ws::WsAppState {
            ws_server: ws_server.clone(),
            stream_handlers: ws_handlers,
        };

        app = app.merge(ws::app_ws(ws_state));
    }

    // HTTPS admin server with mTLS client-certificate authentication.
    //
    // When a CA certificate is available (base_dir/id_ecdsa.crt for the
    // server, and a CA bundle for clients), the HTTPS server requires a valid
    // client certificate. This is the recommended mode for exposing the admin
    // (`/_m/...`) endpoints. Without mTLS, anyone who can reach the port has
    // full admin access (RCE via `_exec`, open relay via `_tcp`/`_uds`).
    if https_port > 0 {
        let cert_path = base_dir.join("id_ecdsa.crt");
        let key_path = base_dir.join("id_ecdsa");
        if cert_path.exists() && key_path.exists() {
            let app = app.clone();
            let https_bind =
                std::env::var("SSH_MESH_HTTPS_BIND").unwrap_or_else(|_| "0.0.0.0".to_string());
            let https_addr = format!("{}:{}", https_bind, https_port);
            // Look for a CA bundle to enable client-cert verification.
            // Defaults to base_dir/authorized_cas (the same file used for SSH
            // CA validation). Can be overridden with SSH_MESH_HTTPS_CA.
            let ca_path = std::env::var("SSH_MESH_HTTPS_CA")
                .map(PathBuf::from)
                .ok()
                .unwrap_or_else(|| base_dir.join("authorized_cas"));
            let ca_arg = if ca_path.exists() {
                info!(
                    "HTTPS admin server will require mTLS client certs validated against {}",
                    ca_path.display()
                );
                Some(ca_path.as_path())
            } else {
                log::warn!(
                    "HTTPS admin server starting WITHOUT client-cert authentication. \
                     The admin endpoints (_exec, _tcp, _uds) will be unauthenticated. \
                     Provide an authorized_cas file or SSH_MESH_HTTPS_CA to enable mTLS."
                );
                None
            };
            match ssh_mesh::auth::TlsServer::new(&cert_path, &key_path, ca_arg, &https_addr) {
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

    // HTTP over UDS server. mesh provides activation/UDS auth; ssh-mesh owns HTTP.
    let control_uds = app_paths
        .control_socket("ssh-mesh")
        .to_string_lossy()
        .into_owned();
    let app_clone = app.clone();
    tokio::spawn(async move {
        if let Err(e) = run_axum_over_mesh_listener("ssh-mesh", Some(&control_uds), app_clone).await
        {
            error!("UDS HTTP server failed: {}", e);
        }
    });

    // HTTP server - forwards to the app's port, with handlers for
    // ssh tunneling and an admin interface.
    //
    // Security: the admin (`/_m/...`) endpoints are served on this port. By
    // default bind to 127.0.0.1 (loopback) so that the admin surface is not
    // reachable from the network without an explicit opt-in. Set
    // `SSH_MESH_HTTP_BIND=0.0.0.0` to listen on all interfaces — only do this
    // behind a reverse proxy or with mTLS on the HTTPS port.
    if http_port > 0 {
        let http_bind =
            std::env::var("SSH_MESH_HTTP_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        if http_bind == "0.0.0.0" || http_bind == "::" {
            log::warn!(
                "HTTP admin server binds {} with unauthenticated admin endpoints (_exec, _tcp, _uds). \
                 Restrict to localhost or use the HTTPS port with mTLS.",
                http_bind
            );
        }
        let listener = if let Some(listener) = mesh::server::take_activated_tcp_listener()
            .map_err(|e| anyhow::anyhow!("activated TCP listener error: {}", e))?
        {
            TcpListener::from_std(listener)?
        } else {
            let http_addr = format!("{}:{}", http_bind, http_port);
            TcpListener::bind(&http_addr).await?
        };
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

async fn run_axum_over_mesh_listener(
    app_name: &str,
    listen_path: Option<&str>,
    app: axum::Router,
) -> Result<(), Box<dyn std::error::Error>> {
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;

    let mut listener = mesh::server::MeshListener::new(app_name, listen_path)?;
    while let Some(stream) = listener.accept().await? {
        let app_clone = app.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, TowerToHyperService::new(app_clone))
                .with_upgrades()
                .await
            {
                let err_str = err.to_string();
                if !err_str.contains("connection error: not connected")
                    && !err_str.contains("early eof")
                {
                    log::error!("UDS HTTP connection failed: {:?}", err);
                }
            }
        });
    }
    Ok(())
}
