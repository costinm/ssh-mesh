use bytes::Bytes;
use fastwebsockets::{upgrade, Frame, Payload, WebSocket};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use log::{error, info};

pub struct WSServer {
    clients: Arc<Mutex<HashMap<String, WebSocket<TokioIo<hyper::upgrade::Upgraded>>>>>,
}

impl WSServer {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
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
