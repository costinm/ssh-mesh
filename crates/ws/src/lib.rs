use bytes::Bytes;
use fastwebsockets::{upgrade, Frame, Payload, WebSocket};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;

type Handler = Arc<
    dyn Fn(
            Request<Incoming>,
            Arc<WSServer>,
        )
            -> Pin<Box<dyn Future<Output = Result<Response<Full<Bytes>>, hyper::Error>> + Send>>
        + Send
        + Sync,
>;

pub struct WSServer {
    clients: Arc<Mutex<HashMap<String, WebSocket<TokioIo<hyper::upgrade::Upgraded>>>>>,
    handlers: Arc<Mutex<HashMap<String, Handler>>>,
}

impl Default for WSServer {
    fn default() -> Self {
        Self::new()
    }
}

impl WSServer {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            handlers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn add_client(&self, id: String, ws: WebSocket<TokioIo<hyper::upgrade::Upgraded>>) {
        debug!("Adding client: {}", id);
        self.clients.lock().await.insert(id.clone(), ws);
        info!(
            "Client added: {}, total clients: {}",
            id,
            self.clients.lock().await.len()
        );
    }

    pub async fn get_client_count(&self) -> usize {
        self.clients.lock().await.len()
    }

    pub async fn remove_client(&self, id: &str) {
        debug!("Removing client: {}", id);
        self.clients.lock().await.remove(id);
        info!(
            "Client removed: {}, remaining clients: {}",
            id,
            self.clients.lock().await.len()
        );
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
        let mut clients = self.clients.lock().await;
        if let Some(ws) = clients.get_mut(id) {
            debug!("Client '{}' found, sending frame", id);
            let frame = Frame::text(Payload::from(message.as_bytes()));
            match ws.write_frame(frame).await {
                Ok(_) => {
                    debug!("Frame sent successfully to client '{}'", id);
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to write frame to client '{}': {}", id, e);
                    Err(e.into())
                }
            }
        } else {
            warn!("Client '{}' not found, cannot send message", id);
            warn!(
                "Available clients: {:?}",
                clients.keys().collect::<Vec<_>>()
            );
            debug!("Message not sent (client not found)");
            Ok(())
        }
    }

    pub async fn broadcast_message(&self, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Broadcasting message: '{}'", message);
        let mut clients = self.clients.lock().await;
        let total_clients = clients.len();
        debug!("Broadcasting to {} clients", total_clients);
        let mut ids_to_remove = Vec::new();

        for (id, ws) in clients.iter_mut() {
            debug!("Sending broadcast to client: {}", id);
            let frame = Frame::text(Payload::from(message.as_bytes()));
            if let Err(e) = ws.write_frame(frame).await {
                error!("Failed to send broadcast to client {}: {}", id, e);
                ids_to_remove.push(id.clone());
            } else {
                debug!("Broadcast sent to client: {}", id);
            }
        }

        // Clean up disconnected clients
        if !ids_to_remove.is_empty() {
            warn!("Removing {} disconnected clients", ids_to_remove.len());
            for id in &ids_to_remove {
                clients.remove(id);
            }
        }

        info!(
            "Broadcast complete: sent to {}/{} clients",
            total_clients - ids_to_remove.len(),
            total_clients
        );
        Ok(())
    }

    pub async fn add_handler<F>(&self, path: String, handler: F)
    where
        F: Fn(
                Request<Incoming>,
                Arc<WSServer>,
            )
                -> Pin<Box<dyn Future<Output = Result<Response<Full<Bytes>>, hyper::Error>> + Send>>
            + Send
            + Sync
            + 'static,
    {
        self.handlers.lock().await.insert(path, Arc::new(handler));
    }

    pub async fn remove_handler(&self, path: &str) {
        self.handlers.lock().await.remove(path);
    }

    pub async fn start(&self, port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        let listener = tokio::net::TcpListener::bind(addr).await?;

        info!("Server listening on http://{}", addr);

        loop {
            let (stream, _) = listener.accept().await?;
            let server = Arc::new(WSServer {
                clients: self.clients.clone(),
                handlers: self.handlers.clone(),
            });

            tokio::task::spawn(async move {
                let io = TokioIo::new(stream);
                let server_clone = server.clone();
                let service = hyper::service::service_fn(move |req| {
                    handle_request(req, server_clone.clone())
                });

                let conn = ConnBuilder::new(TokioExecutor::new());
                let conn = conn.serve_connection_with_upgrades(io, service);

                if let Err(err) = conn.await {
                    error!("Error serving connection: {:?}", err);
                }
            });
        }
    }
}

async fn handle_request(
    req: Request<Incoming>,
    server: Arc<WSServer>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();
    let method = req.method();
    debug!("Incoming request: {} {}", method, path);
    debug!("Headers: {:?}", req.headers());

    let handlers = server.handlers.lock().await;
    if let Some(handler) = handlers.get(path) {
        debug!("Found handler for path: {}", path);
        let handler = handler.clone();
        drop(handlers);
        return handler(req, server).await;
    }

    debug!("No handler found for path: {}", path);
    warn!("Returning 404 for path: {}", path);
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::from("Not Found"))
        .unwrap())
}

pub async fn handle_websocket(
    ws: WebSocket<TokioIo<hyper::upgrade::Upgraded>>,
    server: Arc<WSServer>,
    client_id: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Handling WebSocket connection: {}", client_id);
    server.add_client(client_id.clone(), ws).await;

    let mut clients = server.clients.lock().await;
    loop {
        if let Some(ws) = clients.get_mut(&client_id) {
            match ws.read_frame().await {
                Ok(frame) => {
                    debug!(
                        "Received frame from {}: opcode={:?}, fin={}",
                        client_id, frame.opcode, frame.fin
                    );
                    if frame.fin {
                        debug!("Frame from {} is final", client_id);
                    }
                }
                Err(e) => {
                    debug!("WebSocket read error for {}: {}", client_id, e);
                    drop(clients);
                    server.remove_client(&client_id).await;
                    return Err(e.into());
                }
            }
        } else {
            debug!("Client {} not found in clients map", client_id);
            drop(clients);
            server.remove_client(&client_id).await;
            return Ok(());
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

pub async fn handle_websocket_upgrade(
    mut req: Request<Incoming>,
    server: Arc<WSServer>,
) -> Result<Response<Full<bytes::Bytes>>, hyper::Error> {
    // Check if this is a WebSocket upgrade request
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
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::from("WebSocket upgrade failed"))
                    .unwrap());
            }
        };

        // Create a unique client ID
        let client_id = format!(
            "client_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        info!("WebSocket upgrade successful, client ID: {}", client_id);

        tokio::task::spawn(async move {
            let ws = match fut.await {
                Ok(ws) => {
                    info!("WebSocket connection established for {}", client_id);
                    ws
                }
                Err(e) => {
                    error!("Error upgrading to WebSocket: {}", e);
                    return;
                }
            };

            let client_id_clone = client_id.clone();
            if let Err(e) = handle_websocket(ws, server, client_id).await {
                error!(
                    "Error in WebSocket connection for {}: {}",
                    client_id_clone, e
                );
            }
        });

        // Convert to proper response
        let (parts, _body) = response.into_parts();
        let response = Response::from_parts(parts, Full::from(Bytes::new()));
        Ok(response)
    } else {
        warn!("Request is not a WebSocket upgrade");
        debug!("Request method: {}", req.method());
        debug!("Request URI: {}", req.uri());

        Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::from("Expected WebSocket upgrade"))
            .unwrap())
    }
}

#[derive(Deserialize)]
struct SendMessageRequest {
    message: String,
}

#[derive(Serialize)]
struct ClientsResponse {
    clients: Vec<String>,
}

#[derive(Serialize)]
struct MessageResponse {
    success: bool,
}

pub async fn handle_list_clients(
    _req: Request<Incoming>,
    server: Arc<WSServer>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    debug!("handle_list_clients called");
    let clients = server.list_clients().await;
    debug!("Clients count: {}", clients.len());
    for client in &clients {
        debug!("Client: {}", client);
    }
    let response = ClientsResponse { clients };

    match serde_json::to_string(&response) {
        Ok(json) => {
            debug!("Clients response: {}", json);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::from(json))
                .unwrap())
        }
        Err(e) => {
            error!("Failed to serialize clients response: {}", e);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::from("Failed to serialize response"))
                .unwrap())
        }
    }
}

pub async fn handle_remove_client(
    req: Request<Incoming>,
    server: Arc<WSServer>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();
    debug!("handle_remove_client called with path: {}", path);
    let path_parts: Vec<&str> = path.split('/').collect();

    if path_parts.len() < 4 {
        warn!("Invalid path, not enough parts: {:?}", path_parts);
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::from("Missing client ID"))
            .unwrap());
    }

    let client_id = path_parts[3];
    debug!("Removing client: {}", client_id);
    server.remove_client(client_id).await;

    let response = MessageResponse { success: true };
    match serde_json::to_string(&response) {
        Ok(json) => {
            debug!("Remove client response: {}", json);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::from(json))
                .unwrap())
        }
        Err(e) => {
            error!("Failed to serialize remove client response: {}", e);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::from("Failed to serialize response"))
                .unwrap())
        }
    }
}

pub async fn handle_send_message(
    req: Request<Incoming>,
    server: Arc<WSServer>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();
    debug!("handle_send_message called with path: {}", path);
    let path_parts: Vec<&str> = path.split('/').collect();
    debug!("Path parts: {:?}", path_parts);

    if path_parts.len() < 4 {
        warn!("Invalid path, not enough parts: {:?}", path_parts);
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::from("Missing client ID"))
            .unwrap());
    }

    let client_id = path_parts[3];
    debug!("Target client ID: {}", client_id);

    let body = match req.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            debug!("Request body length: {} bytes", bytes.len());
            debug!("Request body: {:?}", String::from_utf8_lossy(&bytes));
            bytes
        }
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from("Failed to read request body"))
                .unwrap());
        }
    };

    let send_req: SendMessageRequest = match serde_json::from_slice::<SendMessageRequest>(&body) {
        Ok(req) => {
            debug!("Parsed message request: message='{}'", req.message);
            req
        }
        Err(e) => {
            error!("Failed to parse JSON: {}", e);
            error!("Raw body: {:?}", String::from_utf8_lossy(&body));
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from("Invalid JSON"))
                .unwrap());
        }
    };

    let current_clients = server.list_clients().await;
    debug!("Current clients: {:?}", current_clients);
    debug!(
        "Target client exists: {}",
        current_clients.contains(&client_id.to_string())
    );

    match server.send_to_client(client_id, &send_req.message).await {
        Ok(_) => {
            debug!("Message sent successfully to {}", client_id);
            let response = MessageResponse { success: true };
            match serde_json::to_string(&response) {
                Ok(json) => {
                    debug!("Send message response: {}", json);
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(Full::from(json))
                        .unwrap())
                }
                Err(e) => {
                    error!("Failed to serialize response: {}", e);
                    Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::from("Failed to serialize response"))
                        .unwrap())
                }
            }
        }
        Err(e) => {
            error!("Failed to send message to {}: {}", client_id, e);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::from(format!("Failed to send message: {}", e)))
                .unwrap())
        }
    }
}

pub async fn handle_broadcast(
    req: Request<Incoming>,
    server: Arc<WSServer>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    debug!("handle_broadcast called");
    let body = match req.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            debug!("Broadcast request body length: {} bytes", bytes.len());
            debug!(
                "Broadcast request body: {:?}",
                String::from_utf8_lossy(&bytes)
            );
            bytes
        }
        Err(e) => {
            error!("Failed to read broadcast request body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from("Failed to read request body"))
                .unwrap());
        }
    };

    let send_req: SendMessageRequest = match serde_json::from_slice::<SendMessageRequest>(&body) {
        Ok(req) => {
            debug!("Parsed broadcast request: message='{}'", req.message);
            req
        }
        Err(e) => {
            error!("Failed to parse broadcast JSON: {}", e);
            error!("Raw body: {:?}", String::from_utf8_lossy(&body));
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from("Invalid JSON"))
                .unwrap());
        }
    };

    let current_clients = server.list_clients().await;
    debug!("Broadcasting to {} clients", current_clients.len());

    match server.broadcast_message(&send_req.message).await {
        Ok(_) => {
            debug!("Broadcast sent successfully");
            let response = MessageResponse { success: true };
            match serde_json::to_string(&response) {
                Ok(json) => {
                    debug!("Broadcast response: {}", json);
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(Full::from(json))
                        .unwrap())
                }
                Err(e) => {
                    error!("Failed to serialize broadcast response: {}", e);
                    Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::from("Failed to serialize response"))
                        .unwrap())
                }
            }
        }
        Err(e) => {
            error!("Failed to broadcast message: {}", e);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::from(format!("Failed to broadcast message: {}", e)))
                .unwrap())
        }
    }
}
