use anyhow::Error;
use bytes::Bytes;
use http_body_util::Full;
use log::info;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use ws::WSServer;

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

async fn serve_html() -> Full<Bytes> {
    let html_content = include_str!("../web/index.html");
    Full::from(Bytes::from(html_content))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let http_port = env::var("HTTP_PORT")
        .map(|port| port.parse::<u16>().unwrap_or(8083))
        .unwrap_or(8083);

    info!("Starting WebSocket server on port {}", http_port);

    let server = WSServer::new();
    let server = Arc::new(server);

    let html_content = include_str!("../web/index.html");

    // Register HTML handler
    server
        .add_handler("/".to_string(), move |_req, _server: Arc<WSServer>| {
            let html = html_content.clone();
            Box::pin(async move {
                Ok(hyper::Response::builder()
                    .status(hyper::StatusCode::OK)
                    .header("Content-Type", "text/html")
                    .body(Full::from(html))
                    .unwrap())
            })
        })
        .await;

    // Register WebSocket upgrade handler
    server
        .add_handler(
            "/ws".to_string(),
            |req: hyper::Request<hyper::body::Incoming>, server: Arc<WSServer>| {
                Box::pin(async move { ws::handle_websocket_upgrade(req, server).await })
            },
        )
        .await;

    // Register API handlers
    server
        .add_handler(
            "/api/clients".to_string(),
            |req: hyper::Request<hyper::body::Incoming>, server: Arc<WSServer>| {
                Box::pin(async move { ws::handle_list_clients(req, server).await })
            },
        )
        .await;

    server
        .add_handler(
            "/api/clients/".to_string(),
            |req: hyper::Request<hyper::body::Incoming>, server: Arc<WSServer>| {
                Box::pin(async move {
                    let path = req.uri().path();
                    let method = req.method().clone();

                    if method == hyper::Method::DELETE && path.starts_with("/api/clients/") {
                        ws::handle_remove_client(req, server).await
                    } else if method == hyper::Method::POST && path.contains("/message") {
                        ws::handle_send_message(req, server).await
                    } else {
                        Ok(hyper::Response::builder()
                            .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
                            .body(Full::from("Method not allowed"))
                            .unwrap())
                    }
                })
            },
        )
        .await;

    server
        .add_handler(
            "/api/broadcast".to_string(),
            |req: hyper::Request<hyper::body::Incoming>, server: Arc<WSServer>| {
                Box::pin(async move { ws::handle_broadcast(req, server).await })
            },
        )
        .await;

    let _ = server.start(http_port).await;

    Ok(())
}
