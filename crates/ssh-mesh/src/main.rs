use serde::Deserialize;
use std::env;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
#[cfg(feature = "ws")]
use ws::WSServer;

fn get_local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let (log_buffer, _trace_guard) = mesh::local_trace::init("ssh-mesh");
    mesh::local_trace::serve("ssh-mesh", log_buffer);

    // Import required items
    use log::{error, info};
    use ssh_mesh::{
        AppState, ExecConfig, MeshNode, MeshNodeConfig, handlers, run_ssh_server_on_listener,
    };

    let app_paths = mesh::paths::AppPaths::for_app("ssh-mesh");
    let host_ip = get_local_ip().unwrap_or_else(|| "unknown".to_string());

    // Get base directory from environment variable SSH_BASEDIR. If not set,
    // use the ssh-mesh app config directory.
    let base_dir = env::var("SSH_BASEDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| app_paths.etc.clone());

    // Ensure base directory exists
    let _ = std::fs::create_dir_all(&base_dir);

    // Create config from env vars, layering: defaults → config file → env vars
    let cfg: MeshNodeConfig = {
        let mut builder = config::Config::builder()
            .set_default("ssh_port", 15022)
            .unwrap()
            .set_default("http_port", 15080)
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

        match builder.build().and_then(|c| c.try_deserialize()) {
            Ok(mut c) => {
                let c: &mut MeshNodeConfig = &mut c;
                c.base_dir = Some(base_dir.clone());
                c.config_dir = Some(config_dir.clone());
                c.clone()
            }
            Err(e) => {
                log::warn!("Failed to load config via config-rs, using defaults: {}", e);
                MeshNodeConfig {
                    base_dir: Some(base_dir.clone()),
                    config_dir: Some(config_dir.clone()),
                    ssh_port: Some(15022),
                    http_port: Some(15080),
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
        "Starting ssh-mesh with activation fds {:?} SSH_BASEDIR={:?} app_port={:?} ip={}",
        mesh::server::activated_listener_names(),
        base_dir,
        &app_state.target_http_address,
        host_ip
    );

    if let Some(listener) = take_named_or_next_tcp_listener(&["ssh", "ssh-tcp"], "SSH")? {
        let ssh_server_clone = ssh_server.clone();
        tokio::spawn(async move {
            let config = Arc::new(ssh_server_clone.get_config());
            if let Err(e) =
                run_ssh_server_on_listener(listener, config, (*ssh_server_clone).clone()).await
            {
                error!("SSH server failed: {}", e);
            }
        });
    } else {
        log::warn!("no activated SSH TCP listener found");
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

    let web_app = public_web_app(app_paths.home.join("web"));
    start_tls_listener_if_present(
        &base_dir,
        &["h2", "mesh", "mesh-mtls", "mtls"],
        "mesh H2/mTLS",
        app.clone(),
        true,
    )?;
    start_http_listener_if_present(&["http"], "HTTP", web_app.clone(), true)?;
    start_tls_listener_if_present(&base_dir, &["https"], "HTTPS", web_app, true)?;
    start_admin_listener_if_present(app.clone())?;
    start_jsonl_listener_if_present(app_state.ssh_client_manager.clone())?;

    if let Some(listener) =
        take_named_or_next_unix_listener(&["ssh-uds", "trusted-ssh-uds"], "trusted SSH UDS")?
    {
        let trusted_server = ssh_server.clone();
        tokio::spawn(async move {
            if let Err(e) = ssh_mesh::trusted_transport::run_trusted_uds_listener(
                (*trusted_server).clone(),
                listener,
                "ssh-uds",
            )
            .await
            {
                error!("trusted UDS SSH server failed: {}", e);
            }
        });
    }

    if let Some(fd) =
        take_named_or_next_vsock_listener(&["vsock", "ssh-vsock", "trusted-ssh-vsock"], "VSOCK")?
    {
        let trusted_server = ssh_server.clone();
        tokio::spawn(async move {
            match ssh_mesh::trusted_transport::VsockListener::from_owned_fd(fd) {
                Ok(listener) => {
                    if let Err(e) = ssh_mesh::trusted_transport::run_trusted_vsock_listener(
                        (*trusted_server).clone(),
                        listener,
                        "activated".to_string(),
                    )
                    .await
                    {
                        error!("trusted VSOCK SSH server failed: {}", e);
                    }
                }
                Err(e) => error!("trusted VSOCK listener activation failed: {}", e),
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

fn take_named_tcp_listener(names: &[&str]) -> anyhow::Result<Option<TcpListener>> {
    for name in names {
        if let Some(listener) = mesh::server::take_activated_tcp_listener_by_name(name)
            .map_err(|e| anyhow::anyhow!("activated TCP listener '{}' error: {}", name, e))?
        {
            return Ok(Some(TcpListener::from_std(listener)?));
        }
    }
    Ok(None)
}

fn take_named_or_next_tcp_listener(
    names: &[&str],
    role: &str,
) -> anyhow::Result<Option<TcpListener>> {
    if let Some(listener) = take_named_tcp_listener(names)? {
        return Ok(Some(listener));
    }
    if has_activated_listener_names() {
        return Ok(None);
    }
    if let Some(listener) = mesh::server::take_activated_tcp_listener()
        .map_err(|e| anyhow::anyhow!("activated {} listener error: {}", role, e))?
    {
        log::warn!("{} using activated TCP listener by fd order", role);
        return Ok(Some(TcpListener::from_std(listener)?));
    }
    Ok(None)
}

fn take_named_unix_listener(names: &[&str]) -> anyhow::Result<Option<tokio::net::UnixListener>> {
    for name in names {
        if let Some(listener) = mesh::server::take_activated_unix_listener_by_name(name)
            .map_err(|e| anyhow::anyhow!("activated Unix listener '{}' error: {}", name, e))?
        {
            return Ok(Some(listener));
        }
    }
    Ok(None)
}

fn take_named_or_next_unix_listener(
    names: &[&str],
    role: &str,
) -> anyhow::Result<Option<tokio::net::UnixListener>> {
    if let Some(listener) = take_named_unix_listener(names)? {
        return Ok(Some(listener));
    }
    if has_activated_listener_names() {
        return Ok(None);
    }
    if let Some(listener) = mesh::server::take_activated_unix_listener()
        .map_err(|e| anyhow::anyhow!("activated {} listener error: {}", role, e))?
    {
        log::warn!("{} using activated Unix listener by fd order", role);
        return Ok(Some(listener));
    }
    Ok(None)
}

fn take_named_vsock_listener(names: &[&str]) -> anyhow::Result<Option<std::os::fd::OwnedFd>> {
    for name in names {
        if let Some(fd) = mesh::server::take_activated_vsock_listener_by_name(name)
            .map_err(|e| anyhow::anyhow!("activated AF_VSOCK listener '{}' error: {}", name, e))?
        {
            return Ok(Some(fd));
        }
    }
    Ok(None)
}

fn take_named_or_next_vsock_listener(
    names: &[&str],
    role: &str,
) -> anyhow::Result<Option<std::os::fd::OwnedFd>> {
    if let Some(fd) = take_named_vsock_listener(names)? {
        return Ok(Some(fd));
    }
    if has_activated_listener_names() {
        return Ok(None);
    }
    if let Some(fd) = mesh::server::take_activated_vsock_listener()
        .map_err(|e| anyhow::anyhow!("activated {} listener error: {}", role, e))?
    {
        log::warn!("{} using activated AF_VSOCK listener by fd order", role);
        return Ok(Some(fd));
    }
    Ok(None)
}

fn has_activated_listener_names() -> bool {
    !mesh::server::activated_listener_names().is_empty()
}

fn start_http_listener_if_present(
    names: &[&str],
    label: &'static str,
    app: axum::Router,
    allow_order_fallback: bool,
) -> anyhow::Result<()> {
    let listener = if allow_order_fallback {
        take_named_or_next_tcp_listener(names, label)?
    } else {
        take_named_tcp_listener(names)?
    };
    if let Some(listener) = listener {
        tokio::spawn(async move {
            let addr = listener
                .local_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            log::info!("{} listener serving HTTP on {}", label, addr);
            if let Err(e) = axum::serve(listener, app.into_make_service()).await {
                log::error!("{} server failed: {}", label, e);
            }
        });
    }
    Ok(())
}

fn start_admin_listener_if_present(app: axum::Router) -> anyhow::Result<()> {
    if let Some(listener) = take_named_or_next_tcp_listener(&["admin"], "admin HTTP")? {
        tokio::spawn(async move {
            let addr = listener
                .local_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            log::info!("admin listener serving HTTP on {}", addr);
            if let Err(e) = axum::serve(listener, app.into_make_service()).await {
                log::error!("admin HTTP server failed: {}", e);
            }
        });
        return Ok(());
    }

    if let Some(listener) = take_named_unix_listener(&["admin"])? {
        tokio::spawn(async move {
            if let Err(e) = run_axum_over_mesh_stream_listener(listener, app).await {
                log::error!("admin UDS HTTP server failed: {}", e);
            }
        });
    }
    Ok(())
}

fn start_jsonl_listener_if_present(
    manager: Arc<ssh_mesh::sshc::SshClientManager>,
) -> anyhow::Result<()> {
    if let Some(listener) = take_named_or_next_unix_listener(&["jsonl"], "JSONL")? {
        tokio::spawn(async move {
            if let Err(e) = run_jsonl_listener(listener, manager).await {
                log::error!("JSONL listener failed: {}", e);
            }
        });
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method")]
enum SshMeshJsonlRequest {
    #[serde(rename = "sshc/connect")]
    SshcConnect(ssh_mesh::sshc::ConnectRequest),
    #[serde(other)]
    Unknown,
}

async fn run_jsonl_listener(
    listener: tokio::net::UnixListener,
    manager: Arc<ssh_mesh::sshc::SshClientManager>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let (stream, _) = listener.accept().await?;
        let manager = manager.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_jsonl_stream(stream, manager).await {
                log::debug!("JSONL connection failed: {}", e);
            }
        });
    }
}

async fn handle_jsonl_stream(
    stream: tokio::net::UnixStream,
    manager: Arc<ssh_mesh::sshc::SshClientManager>,
) -> anyhow::Result<()> {
    let registry = mesh::jsonl::McpRegistry::new("ssh-mesh");
    let (read, mut write) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(read);
    let mut line = String::new();

    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let manager = manager.clone();
        let (format, response) = mesh::jsonl::dispatch_request::<SshMeshJsonlRequest, _, _>(
            trimmed,
            &registry,
            |request| handle_jsonl_request(manager.clone(), request),
        )
        .await;
        if let Some(response) = response {
            let encoded = mesh::jsonl::format_response(response, &format)?;
            write.write_all(encoded.as_bytes()).await?;
            write.write_all(b"\n").await?;
            write.flush().await?;
        }
    }
    Ok(())
}

async fn handle_jsonl_request(
    manager: Arc<ssh_mesh::sshc::SshClientManager>,
    request: SshMeshJsonlRequest,
) -> mesh::protocol::Response {
    match request {
        SshMeshJsonlRequest::SshcConnect(req) => match manager
            .connect(&req.host, req.port, &req.user, &req.server_key)
            .await
        {
            Ok(id) => mesh::protocol::Response::ok_with_data(serde_json::json!({ "id": id })),
            Err(e) => mesh::protocol::Response::err(e.to_string()),
        },
        SshMeshJsonlRequest::Unknown => {
            mesh::protocol::Response::err("unknown ssh-mesh JSONL method")
        }
    }
}

fn start_tls_listener_if_present(
    base_dir: &std::path::Path,
    names: &[&str],
    label: &'static str,
    app: axum::Router,
    allow_order_fallback: bool,
) -> anyhow::Result<()> {
    let listener = if allow_order_fallback {
        take_named_or_next_tcp_listener(names, label)?
    } else {
        take_named_tcp_listener(names)?
    };
    let Some(listener) = listener else {
        return Ok(());
    };
    let cert_path = base_dir.join("id_ecdsa.crt");
    let key_path = base_dir.join("id_ecdsa");
    if !cert_path.exists() || !key_path.exists() {
        log::error!(
            "{} activated listener present, but TLS cert/key are missing: {} {}",
            label,
            cert_path.display(),
            key_path.display()
        );
        return Ok(());
    }

    let ca_path = std::env::var("SSH_MESH_HTTPS_CA")
        .map(PathBuf::from)
        .ok()
        .unwrap_or_else(|| base_dir.join("authorized_cas"));
    let ca_arg = if ca_path.exists() {
        log::info!(
            "{} will require mTLS client certs validated against {}",
            label,
            ca_path.display()
        );
        Some(ca_path.as_path())
    } else {
        log::warn!(
            "{} starting without client-cert authentication; provide authorized_cas or SSH_MESH_HTTPS_CA to enable mTLS",
            label
        );
        None
    };
    let bind_label = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "activated".to_string());
    let tls_server = ssh_mesh::auth::TlsServer::new(&cert_path, &key_path, ca_arg, &bind_label)?;
    tokio::spawn(async move {
        if let Err(e) =
            ssh_mesh::auth::run_axum_https_listener(listener, tls_server.acceptor, app).await
        {
            log::error!("{} server failed: {}", label, e);
        }
    });
    Ok(())
}

fn public_web_app(web_dir: PathBuf) -> axum::Router {
    axum::Router::new()
        .fallback(public_web_file)
        .with_state(web_dir)
}

async fn public_web_file(
    axum::extract::State(web_dir): axum::extract::State<PathBuf>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> axum::response::Response {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;

    let request_path = uri.path();
    for rel in public_web_candidates(request_path) {
        if let Some(path) = confined_web_path(&web_dir, &rel)
            && path.is_file()
        {
            match tokio::fs::read(&path).await {
                Ok(bytes) => {
                    let mime = mime_guess::from_path(&path)
                        .first_or_octet_stream()
                        .to_string();
                    return (StatusCode::OK, [(header::CONTENT_TYPE, mime)], bytes).into_response();
                }
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("failed to read {}: {}", path.display(), e),
                    )
                        .into_response();
                }
            }
        }
    }

    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

fn public_web_candidates(path: &str) -> Vec<String> {
    let direct = public_web_normalize_path(path);
    let mut out = vec![direct.clone()];
    let parts: Vec<&str> = direct.split('/').filter(|part| !part.is_empty()).collect();
    if parts.len() >= 2 {
        let stripped = if parts.len() == 2 {
            "index.html".to_string()
        } else {
            parts[2..].join("/")
        };
        if stripped != direct {
            out.push(stripped);
        }
    }
    out
}

fn public_web_normalize_path(path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() || trimmed.ends_with('/') {
        format!("{}index.html", trimmed)
    } else {
        trimmed.to_string()
    }
}

fn confined_web_path(web_dir: &Path, rel: &str) -> Option<PathBuf> {
    let mut path = web_dir.to_path_buf();
    for component in Path::new(rel).components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(path)
}

async fn run_axum_over_mesh_stream_listener(
    listener: tokio::net::UnixListener,
    app: axum::Router,
) -> Result<(), Box<dyn std::error::Error>> {
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;

    loop {
        let (stream, _) = listener.accept().await?;
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
}
