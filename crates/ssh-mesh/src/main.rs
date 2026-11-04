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

    let app_paths = mesh::paths::AppPaths::for_accessible_app("ssh-mesh");
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
        web_root: std::env::var_os("MESH_HTTP_WEB_DIR").map(std::path::PathBuf::from),
    };

    ssh_mesh::http_proxy::configure(&ssh_server.router, &ssh_server.cfg.http_proxies)?;

    // Mesh services reached over a CBOR seqpacket socket (lmesh): SSH_MESH_MESH_SERVICES.
    for (catalog, result) in app_state.mesh_services().register_from_env() {
        match result {
            Ok(components) => info!("HTTP serves {catalog} components {components:?}"),
            Err(error) => tracing::warn!("HTTP cannot serve {catalog}: {error:#}"),
        }
    }

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

    if let Some(listener) = take_named_or_next_tcp_listener(&["ssh", "ssh-tcp", "ssh-mesh"], "SSH")?
    {
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

    // ACME: HTTP-01 challenges written by `meshkeys acme` are served on every HTTP
    // listener, and its certificates are served on 443 by SNI.
    let (_, acme_www, cert_dir) = ssh_mesh::certs::acme_paths(
        ssh_server.cfg.acme_home.as_deref(),
        ssh_server.cfg.cert_dir.as_deref(),
    );
    let app = app.merge(ssh_mesh::certs::acme_challenge_routes(acme_www.clone()));
    // What a listener reachable from the network may serve: the SSH-over-HTTP
    // entry point and the upstream proxy, but not the admin routes (`_exec`,
    // `_tcp`, `_uds`, the SSH client API, ...), which have no authorization of
    // their own. The full `app` goes only to loopback-bound listeners, to the
    // explicit `admin` listener, and to mTLS listeners that verify client
    // certificates.
    let public_app = public_http_app(app_state.clone())
        .merge(ssh_mesh::certs::acme_challenge_routes(acme_www.clone()));
    let certificates = Arc::new(ssh_mesh::certs::ReloadableCertificates::load(&cert_dir));

    // Authentication per listener (`http_auth` in the config). Credentials are
    // derived from the host key, so nothing is stored. The `:80` listener only
    // serves ACME challenges and static files, and is not authenticated.
    let http_auth = &ssh_server.cfg.http_auth;
    // Generated on first start, next to the SSH host key.
    let master = ssh_mesh::auth::MasterSecret::load_or_generate(&base_dir)?;
    let secrets = ssh_mesh::httpauth::Secrets::from_master(&master);
    let shell_path =
        |path: &std::path::Path| format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"));
    let meshkeys_path = env::current_exe()?.with_file_name("meshkeys");
    let login_command = format!(
        "sudo {} apikey YOUR_ID --keydir {}",
        shell_path(&meshkeys_path),
        shell_path(&base_dir),
    );
    let auth_for = |listener: &str, secure_cookie: bool| {
        let mode = http_auth.mode_for(listener);
        log::info!("{} listener authentication: {:?}", listener, mode);
        ssh_mesh::httpauth::HttpAuth::new(secrets.clone(), mode, http_auth, secure_cookie)
            .with_login_command(login_command.clone())
    };
    let (auth_http, auth_mesh, auth_admin, auth_https) = (
        auth_for("http", false),
        auth_for("mesh", true),
        auth_for("admin", false),
        auth_for("https", true),
    );

    let (http80_app, https_app) =
        public_web_listener_apps(web_app, &auth_https, acme_www, ssh_server.router.clone());
    start_http_listener_if_present(&["http80"], "HTTP :80", http80_app, None, false)?;
    start_tls_listener_if_present(
        &base_dir,
        &["h2", "mesh", "mesh-mtls", "mtls"],
        "mesh H2/mTLS",
        auth_mesh.apply(app.clone()),
        Some(auth_mesh.apply(public_app.clone())),
        true,
    )?;
    start_http_listener_if_present(
        &["http", "h2c"],
        "HTTP",
        auth_http.apply(app.clone()),
        Some(auth_http.apply(public_app)),
        true,
    )?;
    start_acme_https_listener(&base_dir, &["https"], certificates.clone(), https_app)?;
    start_admin_listener_if_present(auth_admin.apply(app.clone()))?;
    start_jsonl_listener_if_present(app_state.ssh_client_manager.clone(), certificates)?;

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

/// The router for a listener bound to `bind`: `full` only for a loopback
/// address, `public` for anything reachable from the network.
///
/// This uses the bind address, not the peer address: a reverse proxy on this
/// host connects from loopback, and must not make network traffic look local.
fn router_for_bind(
    bind: Option<std::net::SocketAddr>,
    full: &axum::Router,
    public: &axum::Router,
) -> axum::Router {
    match bind {
        Some(addr) if addr.ip().is_loopback() => full.clone(),
        _ => public.clone(),
    }
}

/// Serve `app` on the listener named `names`. With `public`, a listener that
/// is not bound to loopback serves `public` instead (see [`router_for_bind`]).
fn start_http_listener_if_present(
    names: &[&str],
    label: &'static str,
    app: axum::Router,
    public: Option<axum::Router>,
    allow_order_fallback: bool,
) -> anyhow::Result<()> {
    let listener = if allow_order_fallback {
        take_named_or_next_tcp_listener(names, label)?
    } else {
        take_named_tcp_listener(names)?
    };
    if let Some(listener) = listener {
        let app = match &public {
            Some(public) => {
                let bind = listener.local_addr().ok();
                let app = router_for_bind(bind, &app, public);
                let admin = bind.is_some_and(|addr| addr.ip().is_loopback());
                log::info!(
                    "{} listener serves {} routes",
                    label,
                    if admin {
                        "all (loopback)"
                    } else {
                        "public only"
                    }
                );
                app
            }
            None => app,
        };
        tokio::spawn(async move {
            let addr = listener
                .local_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            log::info!("{} listener serving HTTP on {}", label, addr);

            let mut auto =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            auto.http2().enable_connect_protocol();

            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(res) => res,
                    Err(_) => continue,
                };

                let io = hyper_util::rt::TokioIo::new(stream);
                let service = hyper_util::service::TowerToHyperService::new(app.clone());
                let auto = auto.clone();

                tokio::spawn(async move {
                    if let Err(err) = auto.serve_connection(io, service).await {
                        log::debug!("HTTP connection error: {:?}", err);
                    }
                });
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
    certificates: Arc<ssh_mesh::certs::ReloadableCertificates>,
) -> anyhow::Result<()> {
    if let Some(listener) = take_named_or_next_unix_listener(&["jsonl"], "JSONL")? {
        tokio::spawn(async move {
            if let Err(e) = run_jsonl_listener(listener, manager, certificates).await {
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
    #[serde(rename = "certs/reload")]
    CertsReload(ssh_mesh::api::SshMeshCertsReloadRequest),
    #[serde(other)]
    Unknown,
}

async fn run_jsonl_listener(
    listener: tokio::net::UnixListener,
    manager: Arc<ssh_mesh::sshc::SshClientManager>,
    certificates: Arc<ssh_mesh::certs::ReloadableCertificates>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let (stream, _) = listener.accept().await?;
        let manager = manager.clone();
        let certificates = certificates.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_jsonl_stream(stream, manager, certificates).await {
                log::debug!("JSONL connection failed: {}", e);
            }
        });
    }
}

async fn handle_jsonl_stream(
    stream: tokio::net::UnixStream,
    manager: Arc<ssh_mesh::sshc::SshClientManager>,
    certificates: Arc<ssh_mesh::certs::ReloadableCertificates>,
) -> anyhow::Result<()> {
    let registry = mesh::registry::ServiceRegistry::new("ssh-mesh").with_tools_json(
        serde_json::from_str(include_str!("../resources/tools.json"))?,
    );
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
            |request| handle_jsonl_request(manager.clone(), certificates.clone(), request),
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
    certificates: Arc<ssh_mesh::certs::ReloadableCertificates>,
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
        SshMeshJsonlRequest::CertsReload(req) => match tokio::task::spawn_blocking(move || {
            certificates.reload(
                req.certificates
                    .map(|paths| paths.into_iter().map(PathBuf::from).collect()),
            )
        })
        .await
        {
            Ok(Ok(loaded)) => {
                mesh::protocol::Response::ok_with_data(serde_json::json!({ "loaded": loaded }))
            }
            Ok(Err(e)) => mesh::protocol::Response::err(e.to_string()),
            Err(e) => mesh::protocol::Response::err(e.to_string()),
        },
        SshMeshJsonlRequest::Unknown => {
            mesh::protocol::Response::err("unknown ssh-mesh JSONL method")
        }
    }
}

/// Serve `app` over TLS on the listener named `names`. Without client-cert
/// authentication (no CA configured), `without_mtls` is served instead when
/// given, so unauthenticated clients never reach the routes of `app`.
fn start_tls_listener_if_present(
    base_dir: &std::path::Path,
    names: &[&str],
    label: &'static str,
    app: axum::Router,
    without_mtls: Option<axum::Router>,
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
            "{} starting without client-cert authentication; provide authorized_cas or SSH_MESH_HTTPS_CA to enable mTLS{}",
            label,
            if without_mtls.is_some() {
                " (serving public routes only until then)"
            } else {
                ""
            }
        );
        None
    };
    let app = match (ca_arg, without_mtls) {
        (None, Some(public)) => public,
        _ => app,
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

/// Serve `app` over TLS with the ACME certificates chosen by SNI.
fn start_acme_https_listener(
    base_dir: &Path,
    names: &[&str],
    certificates: Arc<ssh_mesh::certs::ReloadableCertificates>,
    app: axum::Router,
) -> anyhow::Result<()> {
    let Some(listener) = take_named_or_next_tcp_listener(names, "HTTPS")? else {
        return Ok(());
    };
    // Preserve the previous TLS configuration until explicit certificate reload
    // installs the first ACME certificates. Even without a legacy key, keep
    // listening so first issuance does not need a process restart.
    let fallback = if certificates.is_empty()
        && base_dir.join("id_ecdsa.crt").exists()
        && base_dir.join("id_ecdsa").exists()
    {
        let ca = std::env::var("SSH_MESH_HTTPS_CA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| base_dir.join("authorized_cas"));
        Some(
            ssh_mesh::auth::TlsServer::new(
                &base_dir.join("id_ecdsa.crt"),
                &base_dir.join("id_ecdsa"),
                ca.exists().then_some(ca.as_path()),
                "HTTPS",
            )?
            .acceptor,
        )
    } else {
        None
    };
    let acceptor = certificates.acceptor(fallback);
    log::info!(
        "HTTPS listener serving ACME certificates on {}",
        listener
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "activated".to_string())
    );
    tokio::spawn(async move {
        if let Err(e) = ssh_mesh::auth::run_axum_https_listener(listener, acceptor, app).await {
            log::error!("HTTPS server failed: {}", e);
        }
    });
    Ok(())
}

/// Public remote transports that authenticate their own callers.
fn public_http_app(state: ssh_mesh::AppState) -> axum::Router {
    let app = ssh_mesh::handlers::app_core(state.clone());
    #[cfg(feature = "ws")]
    let app = app.merge(ws::stream_proxy_routes(vec![(
        "/_m/_ws/_ssh".to_string(),
        Arc::new(ssh_mesh::handlers::SshWsHandler {
            ssh_server: state.ssh_server,
        }),
    )]));
    app
}

fn public_web_listener_apps(
    web: axum::Router,
    https_auth: &ssh_mesh::httpauth::HttpAuth,
    www: PathBuf,
    router: Arc<ssh_mesh::router::Router>,
) -> (axum::Router, axum::Router) {
    let plain = ssh_mesh::certs::acme_challenge_routes(www).merge(web.clone());
    let secure = https_auth.apply_web(ssh_mesh::http_proxy::routes(router, web));
    (plain, secure)
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use axum::{body::Body, routing::get};
    use tower::Service;

    async fn status(mut router: axum::Router, path: &str) -> StatusCode {
        let request = Request::get(path).body(Body::empty()).unwrap();
        router.call(request).await.unwrap().status()
    }

    fn auth() -> ssh_mesh::httpauth::HttpAuth {
        use ssh_mesh::{
            auth::MasterSecret,
            httpauth::{AuthMode, HttpAuth, HttpAuthConfig, Secrets},
        };
        HttpAuth::new(
            Secrets::from_master(&MasterSecret::from_bytes([7; 32])),
            AuthMode::Login,
            &HttpAuthConfig::default(),
            true,
        )
    }

    #[tokio::test]
    async fn port80_does_not_inherit_https_authentication_or_proxy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "public").unwrap();
        let www = dir.path().join("www");
        std::fs::create_dir_all(www.join(".well-known/acme-challenge")).unwrap();
        std::fs::write(www.join(".well-known/acme-challenge/token"), "proof").unwrap();
        let node = ssh_mesh::MeshNode::new(Some(dir.path().join("keys")), Some(Default::default()));
        ssh_mesh::http_proxy::configure(
            &node.router,
            &std::collections::HashMap::from([(
                "oc.example.org".to_string(),
                "127.0.0.1:9".to_string(),
            )]),
        )
        .unwrap();
        let (plain, secure) = public_web_listener_apps(
            public_web_app(dir.path().to_owned()),
            &auth(),
            www,
            node.router.clone(),
        );
        assert_eq!(status(plain.clone(), "/").await, StatusCode::OK);
        let response = plain
            .clone()
            .call(
                Request::get("/")
                    .header("host", "oc.example.org")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            status(plain.clone(), "/.well-known/acme-challenge/token").await,
            StatusCode::OK
        );
        // The web root has an SPA fallback; this path serves the public index,
        // not a login form, and posting a credential never issues a cookie.
        let response = plain
            .clone()
            .call(
                Request::post("/_m/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("key=alice:secret"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!response.headers().contains_key("set-cookie"));
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(&body[..], b"public");
        assert_eq!(status(secure.clone(), "/").await, StatusCode::UNAUTHORIZED);
        assert_eq!(status(secure, "/_m/login").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn local_admin_dispatches_certificate_reload() {
        let setup = ssh_mesh::test_utils::setup_test_environment(None, false)
            .await
            .unwrap();
        let manager = Arc::new(ssh_mesh::sshc::SshClientManager::new(
            setup.mesh_node.private_key().clone(),
            vec![],
            None,
            None,
        ));
        let dir = tempfile::tempdir().unwrap();
        let certs = Arc::new(ssh_mesh::certs::ReloadableCertificates::load(dir.path()));
        let path = dir.path().join("first.crt");
        let ck = rcgen::generate_simple_self_signed(vec!["first.example.org".into()]).unwrap();
        std::fs::write(&path, ck.cert.pem()).unwrap();
        std::fs::write(path.with_extension("key"), ck.signing_key.serialize_pem()).unwrap();
        let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
        let service = tokio::spawn(handle_jsonl_stream(server, manager, certs.clone()));
        let request = serde_json::json!({"jsonrpc":"2.0", "id":7,
            "method":"certs/reload", "params":{"certificates":[path]}});
        client
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        let mut client = tokio::io::BufReader::new(client);
        let mut line = String::new();
        client.read_line(&mut line).await.unwrap();
        let response: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], 7);
        assert_eq!(response["result"]["loaded"], 1, "{response}");
        assert!(!certs.is_empty());
        drop(client);
        service.await.unwrap().unwrap();
    }

    #[cfg(feature = "ws")]
    #[tokio::test]
    async fn public_ssh_websocket_is_exempt_but_admin_routes_stay_absent() {
        let setup = ssh_mesh::test_utils::setup_test_environment(None, false)
            .await
            .unwrap();
        let state = ssh_mesh::AppState {
            ssh_server: setup.mesh_node.clone(),
            target_http_address: None,
            ssh_client_manager: Arc::new(ssh_mesh::sshc::SshClientManager::new(
                setup.mesh_node.private_key().clone(),
                vec![],
                None,
                None,
            )),
            web_root: None,
        };
        let app = auth().apply(public_http_app(state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let response = reqwest::Client::new()
            .get(format!("http://{addr}/_m/_ws/_ssh"))
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        let public = public_http_app(ssh_mesh::AppState {
            ssh_server: setup.mesh_node.clone(),
            target_http_address: None,
            ssh_client_manager: Arc::new(ssh_mesh::sshc::SshClientManager::new(
                setup.mesh_node.private_key().clone(),
                vec![],
                None,
                None,
            )),
            web_root: None,
        });
        for path in [
            "/_m/api/clients",
            "/_m/_ws/_tcp/localhost/80",
            "/_m/_exec/ls",
        ] {
            assert_eq!(status(public.clone(), path).await, StatusCode::NOT_FOUND);
        }
        server.abort();
    }

    #[tokio::test]
    async fn only_loopback_binds_get_the_full_router() {
        let full = axum::Router::new().route("/full", get(|| async { "x" }));
        let public = axum::Router::new().route("/public", get(|| async { "x" }));
        let binds = [
            (Some("127.0.0.1:8080"), true),
            (Some("[::1]:8080"), true),
            (Some("0.0.0.0:8080"), false),
            (Some("[::]:8080"), false),
            (Some("10.0.0.5:8080"), false),
            (None, false),
        ];
        for (bind, loopback) in binds {
            let bind = bind.map(|b| b.parse().unwrap());
            let router = router_for_bind(bind, &full, &public);
            let (served, other) = if loopback {
                ("/full", "/public")
            } else {
                ("/public", "/full")
            };
            assert_eq!(
                status(router.clone(), served).await,
                StatusCode::OK,
                "{bind:?}"
            );
            assert_eq!(
                status(router, other).await,
                StatusCode::NOT_FOUND,
                "{bind:?}"
            );
        }
    }
}
