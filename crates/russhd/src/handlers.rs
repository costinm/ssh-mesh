use crate::ConnectedClientInfo;
use crate::ConnectedClientInfo;
use crate::SshServer;
use crate::SshServer;
use bytes::Bytes;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response};
use hyper::{body::Incoming, Request, Response};
use serde::{Deserialize, Serialize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::Mutex;

/// Data structure to represent connected clients for the UI
#[derive(Serialize, Deserialize, Debug)]
pub struct ClientInfo {
    pub id: usize,
    pub user: String,
    pub remote_forward_listeners: Vec<(String, u32)>,
    pub connected_at: String,
}

/// Get all connected clients and their remote forward listeners
pub async fn get_connected_clients(
    server: &SshServer,
) -> Result<Vec<ClientInfo>, Box<dyn std::error::Error + Send + Sync>> {
    let connected_clients = server.connected_clients.lock().await;
    let mut clients_info = Vec::new();

    for (_, client_info) in connected_clients.iter() {
        clients_info.push(ClientInfo {
            id: client_info.id,
            user: client_info.user.clone(),
            remote_forward_listeners: client_info.remote_forward_listeners.clone(),
            connected_at: client_info
                .connected_at
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::from_secs(0))
                .as_secs()
                .to_string(),
        });
    }

    Ok(clients_info)
}

/// Handler to display connected clients and remote forward listeners
pub async fn handle_connected_clients(
    _req: Request<Incoming>,
    server: SshServer,
) -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    match get_connected_clients(&server).await {
        Ok(clients) => {
            let response_body = serde_json::to_string(&clients).unwrap();
            let response = Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(response_body)))
                .unwrap();
            Ok(response)
        }
        Err(e) => {
            let response = Response::builder()
                .status(500)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(format!("Error: {}", e))))
                .unwrap();
            Ok(response)
        }
    }
}

/// Get all connected clients and their remote forward listeners
pub async fn get_connected_clients(
    server: &SshServer,
) -> Result<Vec<ClientInfo>, Box<dyn std::error::Error + Send + Sync>> {
    let connected_clients = server.connected_clients.lock().await;
    let mut clients_info = Vec::new();

    for (_, client_info) in connected_clients.iter() {
        clients_info.push(ClientInfo {
            id: client_info.id,
            user: client_info.user.clone(),
            remote_forward_listeners: client_info.remote_forward_listeners.clone(),
            connected_at: client_info
                .connected_at
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::from_secs(0))
                .as_secs()
                .to_string(),
        });
    }

    Ok(clients_info)
}

/// Handler to display connected clients and remote forward listeners
pub async fn handle_connected_clients(
    req: Request<Incoming>,
    server: SshServer,
) -> Result<Response<Full<Bytes>>, hyper::http::Error> {
    match get_connected_clients(&server).await {
        Ok(clients) => {
            let response_body = serde_json::to_string(&clients).unwrap();
            let response = Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(response_body)))
                .unwrap();
            Ok(response)
        }
        Err(e) => {
            let response = Response::builder()
                .status(500)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(format!("Error: {}", e))))
                .unwrap();
            Ok(response)
        }
    }
}
