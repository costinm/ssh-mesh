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

pub async fn handle_websocket_upgrade(
    State(server): State<Arc<WSServer>>,
    req: Request,
) -> Response {
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

/// A wrapper around `WebSocket` that implements `AsyncRead` and `AsyncWrite`.
/// This allows using a WebSocket as a byte stream.
pub struct WebSocketStream {
    ws: WebSocket<TokioIo<hyper::upgrade::Upgraded>>,
    read_buffer: bytes::BytesMut,
}

impl WebSocketStream {
    pub fn new(ws: WebSocket<TokioIo<hyper::upgrade::Upgraded>>) -> Self {
        Self {
            ws,
            read_buffer: bytes::BytesMut::new(),
        }
    }
}

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

impl AsyncRead for WebSocketStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.read_buffer.len());
            buf.put_slice(&self.read_buffer[..to_read]);
            self.read_buffer.advance(to_read);
            return Poll::Ready(Ok(()));
        }

        match self.ws.poll_read_frame(cx) {
            Poll::Ready(Ok(frame)) => {
                if frame.opcode == OpCode::Binary || frame.opcode == OpCode::Text {
                    let data = &frame.payload;
                    let to_read = std::cmp::min(buf.remaining(), data.len());
                    buf.put_slice(&data[..to_read]);
                    if to_read < data.len() {
                        self.read_buffer.extend_from_slice(&data[to_read..]);
                    }
                    Poll::Ready(Ok(()))
                } else if frame.opcode == OpCode::Close {
                    Poll::Ready(Ok(()))
                } else {
                    // Ignore other frames for now or handle them
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("WebSocket error: {}", e),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WebSocketStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let frame = Frame::binary(Payload::Owned(buf.to_vec()));
        match self.ws.poll_write_frame(cx, frame) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("WebSocket error: {}", e),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.ws.poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("WebSocket error: {}", e),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let frame = Frame::close(1000, b"shutting down");
        match self.ws.poll_write_frame(cx, frame) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("WebSocket error: {}", e),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct ClientsResponse {
    pub clients: Vec<String>,
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub success: bool,
}

pub async fn handle_list_clients(State(server): State<Arc<WSServer>>) -> Json<ClientsResponse> {
    debug!("handle_list_clients called");
    let clients = server.list_clients().await;
    debug!("Clients count: {}", clients.len());
    for client in &clients {
        debug!("Client: {}", client);
    }
    Json(ClientsResponse { clients })
}

pub async fn handle_remove_client(
    State(server): State<Arc<WSServer>>,
    Path(client_id): Path<String>,
) -> Json<MessageResponse> {
    debug!("Removing client: {}", client_id);
    server.remove_client(&client_id).await;
    Json(MessageResponse { success: true })
}

pub async fn handle_send_message(
    State(server): State<Arc<WSServer>>,
    Path(client_id): Path<String>,
    Json(payload): Json<SendMessageRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
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

pub async fn handle_broadcast(
    State(server): State<Arc<WSServer>>,
    Json(payload): Json<SendMessageRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
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
