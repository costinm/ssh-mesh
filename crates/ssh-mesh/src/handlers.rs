use axum::{
    Router,
    body::Body,
    extract::{Path as AxumPath, State},
    http::{Method, Request, StatusCode},
    response::{Html, IntoResponse, Json, Response},
    routing::{any, delete, get, post},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use log::{debug, info};
use russh::server::Server;
use rust_embed::RustEmbed;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UnixStream};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tracing::{error as tracing_error, instrument};

#[derive(RustEmbed)]
#[folder = "web/"]
pub struct Assets;

use crate::AppState;

pub fn app(app_state: AppState) -> Router {
    Router::new()
        .route("/_m/adm", get(serve_index))
        .route("/_m/adm/*path", get(handle_web_request))
        // WebSocket equivalents
        .route("/_m/_ws/_ssh", get(handle_ws_ssh))
        .route("/_m/_ws/_tcp/:host/:port", get(handle_ws_tcp_proxy))
        .route("/_m/_ws/_uds", get(handle_ws_uds_proxy))
        .route("/_m/_ws/_uds/*path", get(handle_ws_uds_proxy))
        .route("/_m/_ws/_exec/*cmd", get(handle_ws_exec))
        .route("/_m/_ssh", any(handle_ssh_request))
        .route("/_m/_ssh/*rest", any(handle_ssh_request))
        .route("/_m/_tcp/:host/:port", any(handle_tcp_proxy))
        .route("/_m/_uds", any(handle_uds_proxy))
        .route("/_m/_uds/*path", any(handle_uds_proxy))
        .route("/_m/_exec/*cmd", any(handle_exec))
        .fallback(handle_proxy_request)
        .route(
            "/_m/ws",
            get(move |State(app_state): State<AppState>, req| {
                ws::handle_websocket_upgrade(State(app_state.ws_server), req)
            }),
        )
        .route("/_m/api/ssh/clients", get(get_ssh_clients))
        .route(
            "/_m/api/clients",
            get(move |State(app_state): State<AppState>| {
                ws::handle_list_clients(State(app_state.ws_server))
            }),
        )
        .route(
            "/_m/api/clients/:id",
            delete(move |State(app_state): State<AppState>, path| {
                ws::handle_remove_client(State(app_state.ws_server), path)
            }),
        )
        .route(
            "/_m/api/clients/:id/message",
            post(move |State(app_state): State<AppState>, path, json| {
                ws::handle_send_message(State(app_state.ws_server), path, json)
            }),
        )
        .route(
            "/_m/api/broadcast",
            post(move |State(app_state): State<AppState>, json| {
                ws::handle_broadcast(State(app_state.ws_server), json)
            }),
        )
        .with_state(app_state)
}

fn mime_for_path(path: &str) -> String {
    mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string()
}

pub async fn handle_web_request(
    AxumPath(path): AxumPath<String>,
) -> impl axum::response::IntoResponse {
    let path = path.trim_start_matches('/');
    // Check local filesystem first (for dev)
    let local_path = Path::new("web").join(path);

    if local_path.exists() && local_path.is_file() {
        match std::fs::read(&local_path) {
            Ok(content) => {
                let mime = mime_for_path(&local_path.to_string_lossy());
                return (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, mime)],
                    content,
                )
                    .into_response();
            }
            Err(_) => {}
        }
    }

    match Assets::get(path) {
        Some(content) => {
            let mime = mime_for_path(path);
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, mime)],
                content.data.to_owned(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

async fn serve_index() -> impl IntoResponse {
    match Assets::get("ssh.html") {
        Some(content) => Html(std::str::from_utf8(&content.data).unwrap().to_string()),
        None => Html("<h1>Error: ssh.html not found</h1>".to_string()),
    }
}

async fn get_ssh_clients(State(app_state): State<AppState>) -> impl IntoResponse {
    let clients = app_state.ssh_server.connected_clients.lock().await;
    (StatusCode::OK, Json(clients.clone()))
}

// SSH handler for /_ssh* paths - handles SSH over HTTP/2
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
    let stream = crate::utils::ChannelStream {
        reader: reader_rx,
        writer: writer_tx,
        read_buf: bytes::BytesMut::new(),
    };

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

            let response = Response::builder()
                .status(200)
                .body(Body::from_stream(response_stream))
                .unwrap();

            response
        }
        Err(e) => {
            tracing_error!("Failed to start SSH session: {:?}", e);
            let response = Response::builder()
                .status(500)
                .body(Body::from(format!("SSH session failed: {:?}", e)))
                .unwrap();
            response
        }
    }
}

async fn pipe_body_to_tx(body: Body, tx: mpsc::Sender<Result<Bytes, std::io::Error>>) {
    let mut body = body;
    while let Some(frame_res) = body.frame().await {
        match frame_res {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    if tx.send(Ok(data)).await.is_err() {
                        return;
                    }
                }
            }
            Err(e) => {
                let _ = tx
                    .send(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Body read error: {}", e),
                    )))
                    .await;
                return;
            }
        }
    }
}

// TCP proxy handler for /_tcp/:host/:port paths
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

    let stream = crate::utils::ChannelStream {
        reader: reader_rx,
        writer: writer_tx,
        read_buf: bytes::BytesMut::new(),
    };

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

    Response::builder()
        .status(200)
        .body(Body::from_stream(response_stream))
        .unwrap()
        .into_response()
}

// UDS proxy handler for /_uds/*path paths
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

    let stream = crate::utils::ChannelStream {
        reader: reader_rx,
        writer: writer_tx,
        read_buf: bytes::BytesMut::new(),
    };

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

    Response::builder()
        .status(200)
        .body(Body::from_stream(response_stream))
        .unwrap()
        .into_response()
}

// Exec handler for /_exec/*cmd paths
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
        if name_str.starts_with("x-e-") {
            let env_name = name_str[4..].to_uppercase().replace('-', "_");
            if let Ok(val_str) = value.to_str() {
                debug!("Setting env var: {}={}", env_name, val_str);
                env_vars.insert(env_name, val_str.to_string());
            }
        }
    }

    let mut child = match Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .envs(env_vars)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing_error!("Failed to spawn command {}: {}", cmd, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to spawn command: {}", e),
            )
                .into_response();
        }
    };

    let stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stderr = child.stderr.take().expect("Failed to open stderr");

    // Create a bidirectional stream adapter for HTTP/2 body
    let (reader_tx, reader_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(100);
    let (writer_tx, writer_rx) = mpsc::channel::<Bytes>(100);

    // Spawn task to read from HTTP request body and feed to adapter
    tokio::spawn(pipe_body_to_tx(req.into_body(), reader_tx));

    let stream = crate::utils::ChannelStream {
        reader: reader_rx,
        writer: writer_tx,
        read_buf: bytes::BytesMut::new(),
    };

    // Forward data between the HTTP/2 stream and the child process
    tokio::spawn(async move {
        // Task to log stderr
        let cmd_clone = cmd.clone();
        tokio::spawn(async move {
            let mut buffer = [0; 8192];
            loop {
                match stderr.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let err_msg = String::from_utf8_lossy(&buffer[..n]);
                        info!("Exec stderr [{}]: {}", cmd_clone, err_msg.trim());
                    }
                    Err(_) => break,
                }
            }
        });

        let child_io = tokio::io::join(stdout, stdin);
        crate::utils::bridge(child_io, stream, &format!("Exec session for {}", cmd)).await;
        let _ = child.wait().await;
        info!("Exec session completed for: {}", cmd);
    });

    // Create response body from writer_rx
    let response_stream =
        tokio_stream::wrappers::ReceiverStream::new(writer_rx).map(Ok::<_, std::io::Error>);

    Response::builder()
        .status(200)
        .body(Body::from_stream(response_stream))
        .unwrap()
        .into_response()
}

// WebSocket SSH handler
#[instrument(skip(req, state), fields(method = %req.method(), uri = %req.uri()))]
pub async fn handle_ws_ssh(State(state): State<AppState>, req: Request<Body>) -> Response {
    println!("handle_ws_ssh: Received connection request");
    ws::handle_upgrade_with_handler(req, move |ws| async move {
        println!("handle_ws_ssh: WebSocket upgraded");
        let mut ssh_server = state.ssh_server.as_ref().clone();
        let config = Arc::new(ssh_server.get_config());
        let handler = ssh_server.new_client(None);

        let (ws_to_ssh_tx, ws_to_ssh_rx) =
            mpsc::unbounded_channel::<Result<Bytes, std::io::Error>>();
        let (ssh_to_ws_tx, ssh_to_ws_rx) = mpsc::unbounded_channel::<Bytes>();

        let stream = crate::utils::UnboundedChannelStream {
            reader: ws_to_ssh_rx,
            writer: ssh_to_ws_tx,
            read_buf: bytes::BytesMut::new(),
        };

        let handler_id = handler.id;
        let connected_clients = ssh_server.connected_clients.clone();

        // Spawn WS bridge
        tokio::spawn(crate::utils::bridge_ws_to_mpsc(
            ws,
            ws_to_ssh_tx,
            ssh_to_ws_rx,
            "WS SSH",
        ));

        // Run SSH over the stream
        match russh::server::run_stream(config, stream, handler).await {
            Ok(session) => {
                info!("WS SSH session started successfully");
                if let Err(e) = session.await {
                    tracing_error!("WS SSH session error: {:?}", e);
                }
                info!("WS SSH session completed");

                // Cleanup
                let mut clients = connected_clients.lock().await;
                clients.remove(&handler_id);
            }
            Err(e) => {
                tracing_error!("Failed to start WS SSH session: {:?}", e);
            }
        }
    })
    .await
}

// WebSocket TCP proxy handler
#[instrument(skip(req, _state), fields(method = %req.method(), uri = %req.uri(), host = %host, port = %port))]
pub async fn handle_ws_tcp_proxy(
    State(_state): State<AppState>,
    AxumPath((host, port)): AxumPath<(String, u32)>,
    req: Request<Body>,
) -> Response {
    ws::handle_upgrade_with_handler(req, move |ws| async move {
        match TcpStream::connect(format!("{}:{}", host, port)).await {
            Ok(tcp_stream) => {
                crate::utils::bridge_ws(ws, tcp_stream, &format!("WS TCP to {}:{}", host, port))
                    .await;
            }
            Err(e) => {
                tracing_error!("WS TCP connect error to {}:{}: {}", host, port, e);
            }
        }
    })
    .await
}

// WebSocket UDS proxy handler
#[instrument(skip(req, _state), fields(method = %req.method(), uri = %req.uri(), path = %path))]
pub async fn handle_ws_uds_proxy(
    State(_state): State<AppState>,
    AxumPath(path): AxumPath<String>,
    req: Request<Body>,
) -> Response {
    let full_path = if path.starts_with('/') {
        path
    } else {
        format!("/{}", path)
    };
    let path_clone = full_path.clone();

    ws::handle_upgrade_with_handler(req, move |ws| async move {
        match UnixStream::connect(&path_clone).await {
            Ok(unix_stream) => {
                crate::utils::bridge_ws(ws, unix_stream, &format!("WS UDS to {}", path_clone))
                    .await;
            }
            Err(e) => {
                tracing_error!("WS UDS connect error to {}: {}", path_clone, e);
            }
        }
    })
    .await
}

// WebSocket Exec handler
#[instrument(skip(req, _state), fields(method = %req.method(), uri = %req.uri(), cmd = %cmd))]
pub async fn handle_ws_exec(
    State(_state): State<AppState>,
    AxumPath(cmd): AxumPath<String>,
    req: Request<Body>,
) -> Response {
    ws::handle_upgrade_with_handler(req, move |ws| async move {
        info!("WS Executing command: {}", cmd);
        let mut child = match Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                tracing_error!("WS Exec spawn error for {}: {}", cmd, e);
                return;
            }
        };

        let stdin = child.stdin.take().expect("Failed to open stdin");
        let stdout = child.stdout.take().expect("Failed to open stdout");
        let mut stderr = child.stderr.take().expect("Failed to open stderr");

        let cmd_clone = cmd.clone();
        tokio::spawn(async move {
            let mut buffer = [0; 8192];
            loop {
                match stderr.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let err_msg = String::from_utf8_lossy(&buffer[..n]);
                        info!("WS Exec stderr [{}]: {}", cmd_clone, err_msg.trim());
                    }
                    Err(_) => break,
                }
            }
        });

        let child_io = tokio::io::join(stdout, stdin);
        crate::utils::bridge_ws(ws, child_io, &format!("WS Exec for {}", cmd)).await;
        let _ = child.wait().await;
        info!("WS Exec session completed for: {}", cmd);
    })
    .await
}

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
    parts.uri = uri_str.parse().unwrap();

    // Update Host header
    parts
        .headers
        .insert(hyper::header::HOST, target_addr.parse().unwrap());

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
