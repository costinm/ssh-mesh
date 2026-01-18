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

    pub async fn add_client(
        &self,
        id: String,
        sender: mpsc::UnboundedSender<Frame<'static>>,
    ) {
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
    mut req: Request,
) -> Response {
    debug!(
        "WebSocket upgrade requested, is_upgrade: {}",
        upgrade::is_upgrade_request(&req)
    );
    debug!("Headers: {:?}", req.headers());

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

        let client_id = format!(
            "client_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        info!("WebSocket upgrade successful, client ID: {}", client_id);

        tokio::task::spawn(async move {
            let ws = match fut.await {
                Ok(ws) => {
                    info!("WebSocket connection established for {}", client_id);
                    ws
                }
                Err(e) => {
                    error!("Error upgrading to WebSocket for {}: {}", client_id, e);
                    return;
                }
            };

            handle_websocket(ws, server, client_id).await;
        });

        let (parts, _body) = response.into_parts();
        Response::from_parts(parts, Body::from(Bytes::new()))
    } else {
        warn!("Request is not a WebSocket upgrade");
        debug!("Request method: {}", req.method());
        debug!("Request URI: {}", req.uri());

        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Expected WebSocket upgrade"))
            .unwrap()
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

    match server
        .send_to_client(&client_id, &payload.message)
        .await
    {
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

use hyper::Uri;

pub async fn static_file_handler(uri: Uri) -> Response<Body> {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() {
        "index.html"
    } else {
        path
    };

    let web_path = format!("web/{}", path);

    if let Ok(content) = tokio::fs::read_to_string(&web_path).await {
        let mime_type = mime_guess::from_path(path).first_or_text_plain();
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", mime_type.as_ref())
            .body(Body::from(content))
            .unwrap()
    } else if path == "index.html" {
        let content = include_str!("../web/index.html");
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html")
            .body(Body::from(content))
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not Found"))
            .unwrap()
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
