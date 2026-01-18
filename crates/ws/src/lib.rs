use bytes::Bytes;
use fastwebsockets::{upgrade, Frame, Payload, WebSocket};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use log::{error, info};
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
        self.clients.lock().await.insert(id, ws);
    }

    pub async fn remove_client(&self, id: &str) {
        self.clients.lock().await.remove(id);
    }

    pub async fn list_clients(&self) -> Vec<String> {
        self.clients.lock().await.keys().cloned().collect()
    }

    pub async fn send_to_client(
        &self,
        id: &str,
        message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ws) = self.clients.lock().await.get_mut(id) {
            let frame = Frame::text(Payload::from(message.as_bytes()));
            ws.write_frame(frame).await?;
        }
        Ok(())
    }

    pub async fn broadcast_message(&self, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut clients = self.clients.lock().await;
        let mut ids_to_remove = Vec::new();

        for (id, ws) in clients.iter_mut() {
            let frame = Frame::text(Payload::from(message.as_bytes()));
            if let Err(e) = ws.write_frame(frame).await {
                error!("Failed to send message to client {}: {}", id, e);
                ids_to_remove.push(id.clone());
            }
        }

        // Clean up disconnected clients
        for id in ids_to_remove {
            clients.remove(&id);
        }

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

    let handlers = server.handlers.lock().await;
    if let Some(handler) = handlers.get(path) {
        let handler = handler.clone();
        drop(handlers);
        return handler(req, server).await;
    }

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
    info!("New WebSocket connection: {}", client_id);

    // Add client to server
    server.add_client(client_id.clone(), ws).await;

    // Keep connection alive - in a real implementation, you would listen for messages
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    }
}

pub async fn handle_websocket_upgrade(
    mut req: Request<Incoming>,
    server: Arc<WSServer>,
) -> Result<Response<Full<bytes::Bytes>>, hyper::Error> {
    // Check if this is a WebSocket upgrade request
    info!("New WebSocket connection handler isupgrade");
    if upgrade::is_upgrade_request(&req) {
        let (response, fut) = match upgrade::upgrade(&mut req) {
            Ok((response, fut)) => (response, fut),
            Err(_e) => {
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

        tokio::task::spawn(async move {
            let ws = match fut.await {
                Ok(ws) => ws,
                Err(e) => {
                    error!("Error upgrading to WebSocket: {}", e);
                    return;
                }
            };

            if let Err(e) = handle_websocket(ws, server, client_id).await {
                error!("Error in WebSocket connection: {}", e);
            }
        });

        // Convert to proper response
        let (parts, _body) = response.into_parts();
        let response = Response::from_parts(parts, Full::from(Bytes::new()));
        Ok(response)
    } else {
        info!("New WebSocket connection not upgrade started");

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
    let clients = server.list_clients().await;
    let response = ClientsResponse { clients };

    match serde_json::to_string(&response) {
        Ok(json) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::from(json))
            .unwrap()),
        Err(_) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::from("Failed to serialize response"))
            .unwrap()),
    }
}

pub async fn handle_remove_client(
    req: Request<Incoming>,
    server: Arc<WSServer>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path_parts: Vec<&str> = req.uri().path().split('/').collect();

    if path_parts.len() < 4 {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::from("Missing client ID"))
            .unwrap());
    }

    let client_id = path_parts[3];
    server.remove_client(client_id).await;

    let response = MessageResponse { success: true };
    match serde_json::to_string(&response) {
        Ok(json) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::from(json))
            .unwrap()),
        Err(_) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::from("Failed to serialize response"))
            .unwrap()),
    }
}

pub async fn handle_send_message(
    req: Request<Incoming>,
    server: Arc<WSServer>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();
    let path_parts: Vec<&str> = path.split('/').collect();

    if path_parts.len() < 4 {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::from("Missing client ID"))
            .unwrap());
    }

    let client_id = path_parts[3];

    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from("Failed to read request body"))
                .unwrap());
        }
    };

    let send_req: SendMessageRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from("Invalid JSON"))
                .unwrap());
        }
    };

    match server.send_to_client(client_id, &send_req.message).await {
        Ok(_) => {
            let response = MessageResponse { success: true };
            match serde_json::to_string(&response) {
                Ok(json) => Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Full::from(json))
                    .unwrap()),
                Err(_) => Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::from("Failed to serialize response"))
                    .unwrap()),
            }
        }
        Err(e) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::from(format!("Failed to send message: {}", e)))
            .unwrap()),
    }
}

pub async fn handle_broadcast(
    req: Request<Incoming>,
    server: Arc<WSServer>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from("Failed to read request body"))
                .unwrap());
        }
    };

    let send_req: SendMessageRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from("Invalid JSON"))
                .unwrap());
        }
    };

    match server.broadcast_message(&send_req.message).await {
        Ok(_) => {
            let response = MessageResponse { success: true };
            match serde_json::to_string(&response) {
                Ok(json) => Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Full::from(json))
                    .unwrap()),
                Err(_) => Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::from("Failed to serialize response"))
                    .unwrap()),
            }
        }
        Err(e) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::from(format!("Failed to broadcast message: {}", e)))
            .unwrap()),
    }
}
