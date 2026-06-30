use crate::ConnectedClientInfo;
use axum::{
    Router,
    body::Body,
    extract::{Path as AxumPath, State},
    http::{Method, Request, StatusCode},
    response::{Html, IntoResponse, Json, Response},
    routing::{any, get},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use log::{debug, info};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use russh::server::Server;
use rust_embed::RustEmbed;
use std::io::{IoSlice, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tracing::{error as tracing_error, instrument};
use utoipa::OpenApi;

#[derive(RustEmbed)]
#[folder = "web/"]
pub struct Assets;

use crate::AppState;

#[derive(OpenApi)]
#[openapi(
    paths(
        get_ssh_clients,
        handle_ssh_request,
        handle_tcp_proxy,
        handle_uds_proxy,
        handle_exec,
        handle_proxy_request
    ),
    components(
        schemas(
            ConnectedClientInfo
        )
    ),
    tags(
        (name = "ssh-mesh", description = "SSH Mesh API")
    )
)]
pub struct ApiDoc;

/// Serve a JSON file from the `web/` directory by path.
///
/// The path is confined to the `web/` directory: any `..` components or
/// absolute paths are rejected to prevent traversal.
async fn serve_json(AxumPath(path): AxumPath<String>) -> impl IntoResponse {
    let confined = confine_to_web_dir(&path);
    let file_path = match confined {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, "invalid path").into_response(),
    };
    match tokio::fs::read_to_string(&file_path).await {
        Ok(content) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            content,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, format!("{} not found", path)).into_response(),
    }
}

/// Resolve a request path to a filesystem path confined within the `web/`
/// directory. Returns `None` if the path escapes `web/` (via `..`, absolute
/// paths, or symlink resolution outside the root).
fn confine_to_web_dir(request_path: &str) -> Option<std::path::PathBuf> {
    let web_root = std::path::Path::new("web");
    let web_root_canonical = std::fs::canonicalize(web_root).ok()?;
    let joined = web_root.join(request_path.trim_start_matches('/'));
    // Canonicalize if the file exists; otherwise canonicalize the parent and
    // re-append the leaf so not-yet-existing files are still checked.
    let canonical = match std::fs::canonicalize(&joined) {
        Ok(c) => c,
        Err(_) => {
            let parent = joined.parent()?;
            let leaf = joined.file_name()?;
            let parent_canonical = std::fs::canonicalize(parent).ok()?;
            parent_canonical.join(leaf)
        }
    };
    if canonical.starts_with(&web_root_canonical) {
        Some(canonical)
    } else {
        None
    }
}

/// appCore is the core handler for H2C - for example in CloudRun
/// or K8S with a Gateway/ztunnel.
///
/// All access to admin interface will be available by creating
/// SSH port forwards.
pub fn app_core(app_state: AppState) -> Router {
    let router = Router::new()
        .route("/_m/_ssh", any(handle_ssh_request))
        .fallback(handle_proxy_request);

    router.with_state(app_state)
}

/// "Mesh" like function, like Istio but using POST.
/// Should be exposed over mTLS (H2 proper).
///
/// SSH can be exposed as a proxy to port 15022.
///
/// WIP: needs authz.
pub fn app_mesh(app_state: AppState) -> Router {
    let router = Router::new()
        .route("/_m/_ssh", any(handle_ssh_request))
        .route("/_m/_tcp/:host/:port", any(handle_tcp_proxy))
        // This could be restricted to a prefix.
        .route("/_m/_uds", any(handle_uds_proxy))
        .route("/_m/_uds/*path", any(handle_uds_proxy))
        // This could be replaced with a configured host:port
        .route("/_m/_exec/*cmd", any(handle_exec))
        .fallback(handle_proxy_request);

    router.with_state(app_state)
}

/// Admin app. Exposed over SSH for admin/authorized_keys.
/// For devel can be exposed locally. Should be on different port
/// from the H2C - and not exposed on H2 directly.
/// Has all other features - for testing.
pub fn app(app_state: AppState) -> Router {
    let router = Router::new()
        .route("/_m/adm", get(serve_index))
        .route("/_m/adm/*path", get(handle_web_request))
        .route("/_m/_ssh", any(handle_ssh_request))
        .route("/_m/_tcp/:host/:port", any(handle_tcp_proxy))
        .route("/_m/_uds", any(handle_uds_proxy))
        .route("/_m/_uds/*path", any(handle_uds_proxy))
        .route("/_m/_exec/*cmd", any(handle_exec))
        .route("/_m/_ssh/*rest", any(handle_ssh_request))
        .nest("/_m/mcp", crate::mcp_proxy::routes())
        .nest("/_m/pmon", crate::pmon_proxy::routes())
        .nest("/_m/trace", crate::trace_proxy::routes())
        .fallback(handle_proxy_request)
        .route("/_m/api/ssh/clients", get(get_ssh_clients))
        .nest_service(
            "/_m/api/sshc",
            crate::sshc::sshc_routes(app_state.ssh_client_manager.clone()),
        )
        // Serve pre-generated OpenAPI schema
        .route("/_m/api/*path", get(serve_json));

    router.with_state(app_state)
}

/// Guess the MIME type for a file path.
fn mime_for_path(path: &str) -> String {
    mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string()
}

/// Serve embedded or local web assets by path.
pub async fn handle_web_request(
    AxumPath(path): AxumPath<String>,
) -> impl axum::response::IntoResponse {
    let path = path.trim_start_matches('/');
    // Check local filesystem first (for dev), confined to web/.
    if let Some(local_path) = confine_to_web_dir(path)
        && local_path.is_file()
        && let Ok(content) = std::fs::read(&local_path)
    {
        let mime = mime_for_path(&local_path.to_string_lossy());
        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, mime)],
            content,
        )
            .into_response();
    }

    match Assets::get(path) {
        Some(content) => {
            let mime = mime_for_path(path);
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, mime)],
                content.data.clone(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

/// Serve the main SSH web UI (ssh.html) as the index page.
async fn serve_index() -> impl IntoResponse {
    match Assets::get("ssh.html") {
        Some(content) => Html(String::from_utf8_lossy(&content.data).into_owned()),
        None => Html("<h1>Error: ssh.html not found</h1>".to_string()),
    }
}

fn response_with_status(status: StatusCode, body: Body) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

#[utoipa::path(
    get,
    path = "/_m/api/ssh/clients",
    tag = "ssh-mesh",
    responses(
        (status = 200, description = "List connected SSH clients", body = Vec<ConnectedClientInfo>)
    )
)]
async fn get_ssh_clients(State(app_state): State<AppState>) -> impl IntoResponse {
    let clients = app_state.ssh_server.connected_clients.lock().await;
    (StatusCode::OK, Json(clients.clone()))
}

/// SSH-over-HTTP/2 handler.
///
/// Bridges a bidirectional HTTP/2 body stream to a `russh` server session,
/// allowing SSH protocol to tunnel over H2C.
#[utoipa::path(
    post,
    path = "/_m/_ssh",
    tag = "ssh-mesh",
    responses(
        (status = 200, description = "SSH session stream"),
        (status = 500, description = "SSH session failed")
    )
)]
#[instrument(skip(req, state), fields(method = %req.method(), uri = %req.uri()))]
pub async fn handle_ssh_request(
    State(state): State<AppState>,
    req: Request<Body>,
) -> impl IntoResponse {
    info!("Received SSH request: {} {}", req.method(), req.uri());

    // Use shared SSH server
    // We clone the server to get a mutable instance (interior mutability handles state)
    // SshServer is designed to be cloned
    let mut ssh_server = state.ssh_server.as_ref().clone();
    let config = Arc::new(ssh_server.get_config());
    let handler = ssh_server.new_client(None);

    // Create a bidirectional stream adapter for HTTP/2 body
    let (reader_tx, reader_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(100);
    let (writer_tx, writer_rx) = mpsc::channel::<Bytes>(100);

    // Spawn task to read from HTTP request body and feed to SSH
    tokio::spawn(pipe_body_to_tx(req.into_body(), reader_tx));

    // Create the bidirectional stream adapter
    let stream = crate::utils::ChannelStream::new(reader_rx, writer_tx);

    let handler_id = handler.id;
    let connected_clients = ssh_server.connected_clients.clone();

    // Run SSH over the HTTP/2 stream
    match russh::server::run_stream(config, stream, handler).await {
        Ok(session) => {
            info!("SSH session started successfully");

            // Spawn task to handle the SSH session
            tokio::spawn(async move {
                if let Err(e) = session.await {
                    tracing_error!("SSH session error: {:?}", e);
                }
                info!("SSH session completed");

                // Explicit cleanup after session ends
                let mut clients = connected_clients.lock().await;
                if clients.remove(&handler_id).is_some() {
                    debug!("Removed client {} from connected_clients", handler_id);
                }
            });

            // Create response body from writer_rx
            // Body::from_stream expects a stream of Bytes (Result<Bytes, Error>)
            let response_stream =
                tokio_stream::wrappers::ReceiverStream::new(writer_rx).map(Ok::<_, std::io::Error>);

            response_with_status(StatusCode::OK, Body::from_stream(response_stream))
        }
        Err(e) => {
            tracing_error!("Failed to start SSH session: {:?}", e);
            response_with_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                Body::from(format!("SSH session failed: {:?}", e)),
            )
        }
    }
}

/// Pipe frames from an HTTP body into an MPSC sender.
async fn pipe_body_to_tx(body: Body, tx: mpsc::Sender<Result<Bytes, std::io::Error>>) {
    let mut body = body;
    while let Some(frame_res) = body.frame().await {
        match frame_res {
            Ok(frame) => {
                if let Ok(data) = frame.into_data()
                    && tx.send(Ok(data)).await.is_err()
                {
                    return;
                }
            }
            Err(e) => {
                let _ = tx
                    .send(Err(std::io::Error::other(format!(
                        "Body read error: {}",
                        e
                    ))))
                    .await;
                return;
            }
        }
    }
}

/// TCP proxy handler.
///
/// Connects to `host:port` via TCP and bridges the connection over the HTTP/2 body stream.
///
/// * `host` — Target hostname or IP.
/// * `port` — Target port number.
#[utoipa::path(
    post,
    path = "/_m/_tcp/{host}/{port}",
    tag = "ssh-mesh",
    params(
        ("host" = String, Path, description = "Target host"),
        ("port" = u32, Path, description = "Target port")
    ),
    responses(
        (status = 200, description = "TCP proxy stream"),
        (status = 405, description = "Method not allowed"),
        (status = 502, description = "Connection failed")
    )
)]
#[instrument(skip(req, _state), fields(method = %req.method(), uri = %req.uri(), host = %host, port = %port))]
pub async fn handle_tcp_proxy(
    State(_state): State<AppState>,
    AxumPath((host, port)): AxumPath<(String, u32)>,
    req: Request<Body>,
) -> impl IntoResponse {
    let method = req.method().clone();
    if method != Method::POST {
        return (StatusCode::METHOD_NOT_ALLOWED, "Use POST").into_response();
    }

    info!(
        "Received TCP proxy request: {} to {}:{}",
        method, host, port
    );

    let target_addr = format!("{}:{}", host, port);
    let tcp_stream = match TcpStream::connect(&target_addr).await {
        Ok(s) => s,
        Err(e) => {
            let err_msg = format!("Failed to connect to {}: {}", target_addr, e);
            tracing_error!("{}", err_msg);
            return (StatusCode::BAD_GATEWAY, err_msg).into_response();
        }
    };

    // Create a bidirectional stream adapter for HTTP/2 body
    let (reader_tx, reader_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(100);
    let (writer_tx, writer_rx) = mpsc::channel::<Bytes>(100);

    // Spawn task to read from HTTP request body and feed to adapter
    tokio::spawn(pipe_body_to_tx(req.into_body(), reader_tx));

    let stream = crate::utils::ChannelStream::new(reader_rx, writer_tx);

    // Forward data between the HTTP/2 stream and the TCP connection
    tokio::spawn(async move {
        crate::utils::bridge(
            tcp_stream,
            stream,
            &format!("TCP session to {}:{}", host, port),
        )
        .await;
    });

    // Create response body from writer_rx
    let response_stream =
        tokio_stream::wrappers::ReceiverStream::new(writer_rx).map(Ok::<_, std::io::Error>);

    response_with_status(StatusCode::OK, Body::from_stream(response_stream)).into_response()
}

/// Unix domain socket proxy handler.
///
/// Connects to a UDS at the given path and bridges it over the HTTP/2 body stream.
///
/// * `path` — Absolute path to the Unix domain socket.
#[utoipa::path(
    post,
    path = "/_m/_uds/{path}",
    tag = "ssh-mesh",
    params(
        ("path" = String, Path, description = "UDS socket path")
    ),
    responses(
        (status = 200, description = "UDS proxy stream"),
        (status = 405, description = "Method not allowed"),
        (status = 502, description = "Connection failed")
    )
)]
#[instrument(skip(req, _state), fields(method = %req.method(), uri = %req.uri(), path = %path))]
pub async fn handle_uds_proxy(
    State(_state): State<AppState>,
    AxumPath(path): AxumPath<String>,
    req: Request<Body>,
) -> impl IntoResponse {
    let method = req.method().clone();
    if method != Method::POST {
        return (StatusCode::METHOD_NOT_ALLOWED, "Use POST").into_response();
    }

    info!("Received UDS proxy request: {} to {}", method, path);

    let full_path = if path.starts_with('/') {
        path.clone()
    } else {
        format!("/{}", path)
    };

    let unix_stream = match UnixStream::connect(&full_path).await {
        Ok(s) => s,
        Err(e) => {
            let err_msg = format!("Failed to connect to UDS {}: {}", full_path, e);
            tracing_error!("{}", err_msg);
            return (StatusCode::BAD_GATEWAY, err_msg).into_response();
        }
    };

    // Create a bidirectional stream adapter for HTTP/2 body
    let (reader_tx, reader_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(100);
    let (writer_tx, writer_rx) = mpsc::channel::<Bytes>(100);

    // Spawn task to read from HTTP request body and feed to adapter
    tokio::spawn(pipe_body_to_tx(req.into_body(), reader_tx));

    let stream = crate::utils::ChannelStream::new(reader_rx, writer_tx);

    // Forward data between the HTTP/2 stream and the UDS connection
    tokio::spawn(async move {
        crate::utils::bridge(
            unix_stream,
            stream,
            &format!("UDS session to {}", full_path),
        )
        .await;
    });

    // Create response body from writer_rx
    let response_stream =
        tokio_stream::wrappers::ReceiverStream::new(writer_rx).map(Ok::<_, std::io::Error>);

    response_with_status(StatusCode::OK, Body::from_stream(response_stream)).into_response()
}

async fn open_mesh_init_exec_stream(
    cmd: String,
    env: std::collections::HashMap<String, String>,
) -> Result<UnixStream, anyhow::Error> {
    let (child_end, parent_end) = std::os::unix::net::UnixStream::pair()?;
    tokio::task::spawn_blocking(move || {
        send_mesh_init_exec_fd_blocking(cmd, env, child_end.into())
    })
    .await
    .map_err(|e| anyhow::anyhow!("mesh-init exec task failed: {}", e))??;

    parent_end.set_nonblocking(true)?;
    Ok(UnixStream::from_std(parent_end)?)
}

fn send_mesh_init_exec_fd_blocking(
    cmd: String,
    env: std::collections::HashMap<String, String>,
    fd: OwnedFd,
) -> Result<(), anyhow::Error> {
    let socket_path = mesh_init_socket_path();
    let mut stream = std::os::unix::net::UnixStream::connect(&socket_path)?;
    let user = std::env::var("USER").unwrap_or_else(|_| "system".to_string());
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let request = mesh::protocol::Request::StartTerminal {
        name: user,
        home,
        uid: unsafe { libc::getuid() },
        gid: Some(unsafe { libc::getgid() }),
        pty: false,
        env,
        context: None,
        command: Some(cmd),
        fd_count: None,
    };
    let line = serde_json::to_string(&request)?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let iov = [IoSlice::new(b"F")];
    let fds = [fd.as_raw_fd()];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)?;

    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            break;
        }
        response.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    anyhow::ensure!(!response.is_empty(), "empty response from mesh-init");
    let response = String::from_utf8(response)?;
    let response: mesh::protocol::Response = serde_json::from_str(response.trim())?;
    if response.success {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "mesh-init exec failed: {}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        ))
    }
}

fn mesh_init_socket_path() -> String {
    if let Ok(path) = std::env::var("MESH_INIT_SOCK") {
        return path;
    }
    mesh::paths::AppPaths::for_app("system")
        .control_socket("mesh-init")
        .to_string_lossy()
        .into_owned()
}

/// Execute a shell command and stream stdin/stdout over the HTTP/2 body.
///
/// Environment variables can be passed via `X-E-<NAME>` request headers.
///
/// * `cmd` — Shell command to execute via `sh -c`.
#[utoipa::path(
    post,
    path = "/_m/_exec/{cmd}",
    tag = "ssh-mesh",
    params(
        ("cmd" = String, Path, description = "Command to execute")
    ),
    responses(
        (status = 200, description = "Command I/O stream"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Spawn failed")
    )
)]
#[instrument(skip(req, _state), fields(method = %req.method(), uri = %req.uri(), cmd = %cmd))]
pub async fn handle_exec(
    State(_state): State<AppState>,
    AxumPath(cmd): AxumPath<String>,
    req: Request<Body>,
) -> impl IntoResponse {
    let method = req.method().clone();
    if method != Method::POST {
        return (StatusCode::METHOD_NOT_ALLOWED, "Use POST").into_response();
    }

    info!("Received Exec request: {} for command: {}", method, cmd);

    // Prepare environment variables from X-E- headers
    let mut env_vars = std::collections::HashMap::new();
    for (name, value) in req.headers() {
        let name_str = name.as_str().to_lowercase();
        if let Some(stripped) = name_str.strip_prefix("x-e-") {
            let env_name = stripped.to_uppercase().replace('-', "_");
            if let Ok(val_str) = value.to_str() {
                debug!("Setting env var: {}={}", env_name, val_str);
                env_vars.insert(env_name, val_str.to_string());
            }
        }
    }

    let mesh_init_stream = match open_mesh_init_exec_stream(cmd.clone(), env_vars).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing_error!("Failed to start mesh-init exec {}: {}", cmd, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to start mesh-init exec: {}", e),
            )
                .into_response();
        }
    };

    // Create a bidirectional stream adapter for HTTP/2 body
    let (reader_tx, reader_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(100);
    let (writer_tx, writer_rx) = mpsc::channel::<Bytes>(100);

    // Spawn task to read from HTTP request body and feed to adapter
    tokio::spawn(pipe_body_to_tx(req.into_body(), reader_tx));

    let stream = crate::utils::ChannelStream::new(reader_rx, writer_tx);

    // Forward data between the HTTP/2 stream and the child process
    tokio::spawn(async move {
        crate::utils::bridge(
            mesh_init_stream,
            stream,
            &format!("Exec session for {}", cmd),
        )
        .await;
        info!("Exec session completed for: {}", cmd);
    });

    // Create response body from writer_rx
    let response_stream =
        tokio_stream::wrappers::ReceiverStream::new(writer_rx).map(Ok::<_, std::io::Error>);

    response_with_status(StatusCode::OK, Body::from_stream(response_stream)).into_response()
}

/// WebSocket handler for SSH-over-WS at `/_m/_ws/_ssh`.
pub struct SshWsHandler {
    pub ssh_server: Arc<crate::MeshNode>,
}

impl mesh::Routable for SshWsHandler {
    fn route(&self) -> &str {
        "/_m/_ws/_ssh"
    }
}

#[async_trait::async_trait]
impl mesh::StreamHandler for SshWsHandler {
    async fn handle(
        &self,
        _dest: &str,
        _headers: &std::collections::HashMap<String, String>,
        stream: tokio::io::DuplexStream,
    ) {
        let mut ssh_server = self.ssh_server.as_ref().clone();
        let config = Arc::new(ssh_server.get_config());
        let handler = ssh_server.new_client(None);
        let handler_id = handler.id;
        let connected_clients = self.ssh_server.connected_clients.clone();

        match russh::server::run_stream(config, stream, handler).await {
            Ok(session) => {
                info!("WS SSH session started successfully");
                if let Err(e) = session.await {
                    tracing_error!("WS SSH session error: {:?}", e);
                }
                info!("WS SSH session completed");

                let mut clients = connected_clients.lock().await;
                clients.remove(&handler_id);
            }
            Err(e) => {
                tracing_error!("Failed to start WS SSH session: {:?}", e);
            }
        }
    }
}

/// WebSocket handler for TCP proxy at `/_m/_ws/_tcp/*path`.
pub struct TcpProxyWsHandler;

impl mesh::Routable for TcpProxyWsHandler {
    fn route(&self) -> &str {
        "/_m/_ws/_tcp/*path"
    }
}

#[async_trait::async_trait]
impl mesh::StreamHandler for TcpProxyWsHandler {
    async fn handle(
        &self,
        dest: &str,
        _headers: &std::collections::HashMap<String, String>,
        stream: tokio::io::DuplexStream,
    ) {
        let parts: Vec<&str> = dest.splitn(5, '/').collect();
        let host_port = parts.get(4).unwrap_or(&"");
        let (host, port) = match host_port.split_once('/') {
            Some((h, p)) => (h, p),
            None => {
                tracing_error!("Invalid TCP proxy dest format: {}", dest);
                return;
            }
        };
        match TcpStream::connect(format!("{}:{}", host, port)).await {
            Ok(tcp_stream) => {
                crate::utils::bridge(tcp_stream, stream, &format!("WS TCP to {}:{}", host, port))
                    .await;
            }
            Err(e) => {
                tracing_error!("WS TCP connect error to {}:{}: {}", host, port, e);
            }
        }
    }
}

/// WebSocket handler for UDS proxy at `/_m/_ws/_uds/*path`.
pub struct UdsProxyWsHandler;

impl mesh::Routable for UdsProxyWsHandler {
    fn route(&self) -> &str {
        "/_m/_ws/_uds/*path"
    }
}

#[async_trait::async_trait]
impl mesh::StreamHandler for UdsProxyWsHandler {
    async fn handle(
        &self,
        dest: &str,
        _headers: &std::collections::HashMap<String, String>,
        stream: tokio::io::DuplexStream,
    ) {
        let parts: Vec<&str> = dest.splitn(5, '/').collect();
        let mut path_clone = String::from("/");
        path_clone.push_str(parts.get(4).unwrap_or(&""));

        match UnixStream::connect(&path_clone).await {
            Ok(unix_stream) => {
                crate::utils::bridge(unix_stream, stream, &format!("WS UDS to {}", path_clone))
                    .await;
            }
            Err(e) => {
                tracing_error!("WS UDS connect error to {}: {}", path_clone, e);
            }
        }
    }
}

/// WebSocket handler for command execution at `/_m/_ws/_exec/*cmd`.
pub struct ExecWsHandler;

impl mesh::Routable for ExecWsHandler {
    fn route(&self) -> &str {
        "/_m/_ws/_exec/*cmd"
    }
}

#[async_trait::async_trait]
impl mesh::StreamHandler for ExecWsHandler {
    async fn handle(
        &self,
        dest: &str,
        _headers: &std::collections::HashMap<String, String>,
        stream: tokio::io::DuplexStream,
    ) {
        let parts: Vec<&str> = dest.splitn(5, '/').collect();
        let cmd = parts.get(4).unwrap_or(&"").to_string();
        info!("WS Executing command: {}", cmd);
        let mesh_init_stream =
            match open_mesh_init_exec_stream(cmd.clone(), Default::default()).await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing_error!("WS mesh-init exec error for {}: {}", cmd, e);
                    return;
                }
            };
        crate::utils::bridge(mesh_init_stream, stream, &format!("WS Exec for {}", cmd)).await;
        info!("WS Exec session completed for: {}", cmd);
    }
}

/// Fallback reverse proxy handler.
///
/// Forwards unmatched requests to `target_http_address` if configured.
#[utoipa::path(
    get,
    path = "/",
    tag = "ssh-mesh",
    responses(
        (status = 200, description = "Proxied response"),
        (status = 404, description = "No target configured"),
        (status = 502, description = "Proxy error")
    )
)]
pub async fn handle_proxy_request(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> impl IntoResponse {
    let target_addr = match &state.target_http_address {
        Some(addr) => addr,
        None => return (StatusCode::NOT_FOUND, "Not Found").into_response(),
    };

    let path = req.uri().path();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    let uri_str = if target_addr.contains(':') {
        format!("http://{}{}{}", target_addr, path, query)
    } else {
        format!("http://127.0.0.1:{}{}{}", target_addr, path, query)
    };

    let (mut parts, body) = req.into_parts();
    parts.uri = match uri_str.parse() {
        Ok(uri) => uri,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("invalid proxy target URI {uri_str}: {error}"),
            )
                .into_response();
        }
    };

    // Update Host header
    let host = match target_addr.parse() {
        Ok(host) => host,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("invalid proxy host header {target_addr}: {error}"),
            )
                .into_response();
        }
    };
    parts.headers.insert(hyper::header::HOST, host);

    let proxy_req = hyper::Request::from_parts(parts, body);

    use hyper_util::client::legacy::Client;
    use hyper_util::client::legacy::connect::HttpConnector;
    let client: Client<HttpConnector, axum::body::Body> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build(HttpConnector::new());

    match client.request(proxy_req).await {
        Ok(res) => res.into_response(),
        Err(err) => (StatusCode::BAD_GATEWAY, format!("Proxy error: {}", err)).into_response(),
    }
}
