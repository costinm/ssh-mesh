use axum::{
    body::Body,
    extract::{Path, Request, State},
    response::Response,
    Json,
};
use bytes::Bytes;
use fastwebsockets::{upgrade, Frame, OpCode, Payload, WebSocket};
use hyper::StatusCode;
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use utoipa::ToSchema;

/// WSServer holds the state of the WebSocket server.
#[derive(Clone, Default)]
pub struct WSServer {
    clients: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<Frame<'static>>>>>,
}

impl WSServer {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn add_client(&self, id: String, sender: mpsc::UnboundedSender<Frame<'static>>) {
        debug!("Adding client: {}", id);
        self.clients.lock().await.insert(id.clone(), sender);
        let new_count = self.clients.lock().await.len();
        info!("Client added: {}, total clients: {}", id, new_count);
    }

    pub async fn get_client_count(&self) -> usize {
        self.clients.lock().await.len()
    }

    pub async fn remove_client(&self, id: &str) {
        debug!("Removing client: {}", id);
        self.clients.lock().await.remove(id);
        let remaining = self.clients.lock().await.len();
        info!("Client removed: {}, remaining clients: {}", id, remaining);
    }

    pub async fn list_clients(&self) -> Vec<String> {
        self.clients.lock().await.keys().cloned().collect()
    }

    pub async fn send_to_client(
        &self,
        id: &str,
        message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!(
            "Attempting to send to client '{}': message='{}'",
            id, message
        );
        let frame = Frame::text(Payload::Owned(message.as_bytes().to_vec()));
        let clients = self.clients.lock().await;
        if let Some(sender) = clients.get(id) {
            if sender.send(frame).is_err() {
                warn!("Failed to send message to client {}: channel closed", id);
            }
        } else {
            warn!("Client '{}' not found, cannot send message", id);
            warn!(
                "Available clients: {:?}",
                clients.keys().collect::<Vec<_>>()
            );
        }
        Ok(())
    }

    pub async fn broadcast_message(&self, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Broadcasting message: '{}'", message);
        let clients = self.clients.lock().await;
        let total_clients = clients.len();
        debug!("Broadcasting to {} clients", total_clients);

        let owned_message = message.as_bytes().to_vec();

        for (id, sender) in clients.iter() {
            let frame = Frame::text(Payload::Owned(owned_message.clone()));
            if sender.send(frame).is_err() {
                warn!("Failed to broadcast to client {}: channel closed", id);
            }
        }

        info!("Broadcast complete: sent to {} clients", total_clients);
        Ok(())
    }
}

pub async fn handle_websocket(
    mut ws: WebSocket<TokioIo<hyper::upgrade::Upgraded>>,
    server: Arc<WSServer>,
    client_id: String,
) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    server.add_client(client_id.clone(), tx).await;

    loop {
        tokio::select! {
            Some(msg) = rx.recv() => {
                if let Err(e) = ws.write_frame(msg).await {
                    error!("WebSocket write error for {}: {}", client_id, e);
                    break;
                }
            }
            result = ws.read_frame() => {
                match result {
                    Ok(frame) => {
                        if frame.opcode == OpCode::Close {
                            debug!("Client {} sent close frame", client_id);
                            break;
                        }
                        debug!("Received frame from {}: opcode={:?}, fin={}", client_id, frame.opcode, frame.fin);
                    }
                    Err(e) => {
                        error!("WebSocket read error for {}: {}", client_id, e);
                        break;
                    }
                }
            }
        }
    }

    server.remove_client(&client_id).await;
}

#[derive(Clone)]
pub struct WsAppState {
    pub ws_server: Arc<WSServer>,
    pub stream_handlers: Vec<(String, Arc<dyn mesh::StreamHandler>)>,
    pub push_handler: Option<Arc<dyn mesh::PushHandler>>,
}

pub async fn handle_websocket_upgrade(State(state): State<WsAppState>, req: Request) -> Response {
    let server = state.ws_server;
    handle_upgrade_with_handler(req, move |ws| async move {
        let client_id = format!(
            "client_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        info!("WebSocket connection established for {}", client_id);
        handle_websocket(ws, server, client_id).await;
    })
    .await
}

pub async fn handle_upgrade_with_handler<F, Fut>(mut req: Request, handler: F) -> Response
where
    F: FnOnce(WebSocket<TokioIo<hyper::upgrade::Upgraded>>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    debug!(
        "WebSocket upgrade requested, is_upgrade: {}",
        upgrade::is_upgrade_request(&req)
    );

    if upgrade::is_upgrade_request(&req) {
        let (response, fut) = match upgrade::upgrade(&mut req) {
            Ok((response, fut)) => (response, fut),
            Err(e) => {
                error!("WebSocket upgrade failed: {}", e);
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("WebSocket upgrade failed"))
                    .unwrap();
            }
        };

        tokio::task::spawn(async move {
            let ws = match fut.await {
                Ok(ws) => ws,
                Err(e) => {
                    error!("Error upgrading to WebSocket: {}", e);
                    return;
                }
            };
            handler(ws).await;
        });

        let (parts, _body) = response.into_parts();
        Response::from_parts(parts, Body::from(Bytes::new()))
    } else {
        warn!("Request is not a WebSocket upgrade");
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Expected WebSocket upgrade"))
            .unwrap()
    }
}

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        handle_list_clients,
        handle_remove_client,
        handle_send_message,
        handle_broadcast
    ),
    components(
        schemas(
            ClientsResponse, MessageResponse, SendMessageRequest
        )
    ),
    tags(
        (name = "ws", description = "WebSocket API")
    )
)]
pub struct WsApiDoc;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct SendMessageRequest {
    pub message: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ClientsResponse {
    pub clients: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct MessageResponse {
    pub success: bool,
}
#[utoipa::path(
    get,
    path = "/_m/api/clients",
    tag = "ws",
    responses(
        (status = 200, description = "List connected WebSocket clients", body = ClientsResponse)
    )
)]
pub async fn handle_list_clients(State(state): State<WsAppState>) -> Json<ClientsResponse> {
    let server = state.ws_server;
    debug!("handle_list_clients called");
    let clients = server.list_clients().await;
    debug!("Clients count: {}", clients.len());
    for client in &clients {
        debug!("Client: {}", client);
    }
    Json(ClientsResponse { clients })
}

#[utoipa::path(
    delete,
    path = "/_m/api/clients/{id}",
    tag = "ws",
    params(
        ("id" = String, Path, description = "Client ID")
    ),
    responses(
        (status = 200, description = "Remove client", body = MessageResponse)
    )
)]
pub async fn handle_remove_client(
    State(state): State<WsAppState>,
    Path(client_id): Path<String>,
) -> Json<MessageResponse> {
    let server = state.ws_server;
    debug!("Removing client: {}", client_id);
    server.remove_client(&client_id).await;
    Json(MessageResponse { success: true })
}

#[utoipa::path(
    post,
    path = "/_m/api/clients/{id}/message",
    tag = "ws",
    params(
        ("id" = String, Path, description = "Client ID")
    ),
    request_body = SendMessageRequest,
    responses(
        (status = 200, description = "Send message to client", body = MessageResponse)
    )
)]
pub async fn handle_send_message(
    State(state): State<WsAppState>,
    Path(client_id): Path<String>,
    Json(payload): Json<SendMessageRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let server = state.ws_server;
    debug!("Target client ID: {}", client_id);

    match server.send_to_client(&client_id, &payload.message).await {
        Ok(_) => {
            debug!("Message sent successfully to {}", client_id);
            Ok(Json(MessageResponse { success: true }))
        }
        Err(e) => {
            error!("Failed to send message to {}: {}", client_id, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[utoipa::path(
    post,
    path = "/_m/api/broadcast",
    tag = "ws",
    request_body = SendMessageRequest,
    responses(
        (status = 200, description = "Broadcast message to all clients", body = MessageResponse)
    )
)]
pub async fn handle_broadcast(
    State(state): State<WsAppState>,
    Json(payload): Json<SendMessageRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let server = state.ws_server;
    debug!("handle_broadcast called");

    match server.broadcast_message(&payload.message).await {
        Ok(_) => {
            debug!("Broadcast sent successfully");
            Ok(Json(MessageResponse { success: true }))
        }
        Err(e) => {
            error!("Failed to broadcast message: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Bridge a WebSocket with an AsyncRead + AsyncWrite target
pub async fn bridge_ws<S, T>(mut ws: WebSocket<S>, mut target: T, label: &str)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        tokio::select! {
            res = ws.read_frame() => {
                match res {
                    Ok(frame) => {
                        match frame.opcode {
                            OpCode::Binary | OpCode::Text => {
                                use tokio::io::AsyncWriteExt;
                                if target.write_all(&frame.payload).await.is_err() {
                                    break;
                                }
                            }
                            OpCode::Close => break,
                            _ => {}
                        }
                    }
                    Err(_) => break,
                }
            }
            res = tokio::io::AsyncReadExt::read(&mut target, &mut buf) => {
                match res {
                    Ok(0) => {
                        // EOF from target
                        let _ = ws.write_frame(Frame::close(1000, b"EOF")).await;
                        break;
                    }
                    Ok(n) => {
                        let frame = Frame::binary(Payload::Owned(buf[..n].to_vec()));
                        if ws.write_frame(frame).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    debug!("WebSocket bridge {} closed", label);
}

/// Bridge a WebSocket with MPSC channels
pub async fn bridge_ws_to_mpsc<S>(
    mut ws: WebSocket<S>,
    tx_to_mpsc: mpsc::UnboundedSender<Result<Bytes, std::io::Error>>,
    mut rx_from_mpsc: mpsc::UnboundedReceiver<Bytes>,
    label: &str,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    debug!("bridge_ws_to_mpsc: Starting bridge for {}", label);
    loop {
        tokio::select! {
            res = ws.read_frame() => {
                match res {
                    Ok(frame) => {
                        match frame.opcode {
                            OpCode::Binary | OpCode::Text => {
                                if tx_to_mpsc.send(Ok(Bytes::from(frame.payload.to_vec()))).is_err() {
                                    break;
                                }
                            }
                            OpCode::Close => {
                                break;
                            },
                            _ => {}
                        }
                    }
                    Err(e) => {
                        error!("WS bridge {}: read error: {}", label, e);
                        break;
                    }
                }
            }
            res = rx_from_mpsc.recv() => {
                match res {
                    Some(data) => {
                        let frame = Frame::binary(Payload::Owned(data.to_vec()));
                        if ws.write_frame(frame).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        let _ = ws.write_frame(Frame::close(1000, b"EOF")).await;
                        break;
                    }
                }
            }
        }
    }
    debug!("WebSocket MPSC bridge {} closed", label);
}

/// Pipe frames from WebSocket to an MPSC sender
pub async fn pipe_ws_to_tx<S>(mut ws: WebSocket<S>, tx: mpsc::Sender<Result<Bytes, std::io::Error>>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Ok(frame) = ws.read_frame().await {
        match frame.opcode {
            OpCode::Binary | OpCode::Text => {
                if tx
                    .send(Ok(Bytes::from(frame.payload.to_vec())))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            OpCode::Close => break,
            _ => {}
        }
    }
}

/// Pipe data from an MPSC receiver to a WebSocket as binary frames
pub async fn pipe_rx_to_ws<S>(mut ws: WebSocket<S>, mut rx: mpsc::Receiver<Bytes>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(data) = rx.recv().await {
        let frame = Frame::binary(Payload::Owned(data.to_vec()));
        if ws.write_frame(frame).await.is_err() {
            break;
        }
    }
    let _ = ws.write_frame(Frame::close(1000, b"EOF")).await;
}

#[async_trait::async_trait]
impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + core::marker::Unpin + Send + 'static>
    mesh::PushSender for GenericWs<S>
{
    async fn send_text(
        &mut self,
        text: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_text(text).await
    }
    async fn recv(&mut self) -> Option<mesh::PushClientMsg> {
        self.recv().await
    }
}

pub struct GenericWs<S> {
    inner: fastwebsockets::WebSocket<S>,
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + core::marker::Unpin> GenericWs<S> {
    pub fn new(inner: fastwebsockets::WebSocket<S>) -> Self {
        Self { inner }
    }

    pub async fn send_text(
        &mut self,
        text: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner
            .write_frame(fastwebsockets::Frame::text(fastwebsockets::Payload::Owned(
                text.into_bytes(),
            )))
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    pub async fn recv(&mut self) -> Option<mesh::PushClientMsg> {
        match self.inner.read_frame().await {
            Ok(frame) => match frame.opcode {
                fastwebsockets::OpCode::Close => Some(mesh::PushClientMsg::Close),
                fastwebsockets::OpCode::Ping | fastwebsockets::OpCode::Pong => {
                    Some(mesh::PushClientMsg::Ping)
                }
                _ => Some(mesh::PushClientMsg::Other),
            },
            Err(_) => None,
        }
    }
}

pub fn app_ws(ws_state: WsAppState) -> axum::Router {
    let mut router = axum::Router::new()
        .route("/_m/ws", axum::routing::get(handle_websocket_upgrade))
        .route("/_m/api/clients", axum::routing::get(handle_list_clients))
        .route(
            "/_m/api/clients/:id",
            axum::routing::delete(handle_remove_client),
        )
        .route(
            "/_m/api/clients/:id/message",
            axum::routing::post(handle_send_message),
        )
        .route("/_m/api/broadcast", axum::routing::post(handle_broadcast));

    if let Some(push_handler) = ws_state.push_handler.clone() {
        router = router.route(
            "/_m/trace/view",
            axum::routing::get(move |req: Request| {
                let ph = push_handler.clone();
                async move {
                    handle_upgrade_with_handler(req, move |ws| async move {
                        ph.handle_push(Box::new(GenericWs::new(ws))).await;
                    })
                    .await
                }
            }),
        );
    }

    for (route, handler) in ws_state.stream_handlers.clone() {
        let h = handler.clone();
        router = router.route(
            &route,
            axum::routing::get(move |req: axum::extract::Request| async move {
                handle_ws_proxy(req, h).await
            }),
        );
    }

    router.with_state(ws_state)
}

async fn handle_ws_proxy(
    req: axum::extract::Request,
    handler: std::sync::Arc<dyn mesh::StreamHandler>,
) -> axum::response::Response {
    let mut headers = HashMap::new();
    for (k, v) in req.headers() {
        if let Ok(value) = v.to_str() {
            headers.insert(k.as_str().to_string(), value.to_string());
        }
    }

    let dest = req.uri().path().to_string();

    handle_upgrade_with_handler(req, move |ws| async move {
        let (stream1, stream2) = tokio::io::duplex(8192);

        let ws_label = format!("ws-{}", dest);

        tokio::spawn(async move {
            bridge_ws(ws, stream1, &ws_label).await;
        });

        handler.handle(&dest, &headers, stream2).await;
    })
    .await
}
