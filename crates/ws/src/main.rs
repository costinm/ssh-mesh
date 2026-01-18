use anyhow::Error;
use axum::{
    routing::{delete, get, post},
    Router,
};
use log::info;
use std::env;
use std::sync::Arc;
use ws::WSServer;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let http_port = env::var("HTTP_PORT")
        .map(|port| port.parse::<u16>().unwrap_or(8083))
        .unwrap_or(8083);

    info!("Starting HTTP and WebSocket server on port {}", http_port);

    let server = Arc::new(WSServer::new());

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/ws", get(ws::handle_websocket_upgrade))
        .route("/api/clients", get(ws::handle_list_clients))
        .route("/api/clients/:id", delete(ws::handle_remove_client))
        .route(
            "/api/clients/:id/message",
            post(ws::handle_send_message),
        )
        .route("/api/broadcast", post(ws::handle_broadcast))
        .with_state(server);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], http_port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .await
        .map_err(|e| Error::new(e))?;

    Ok(())
}

async fn root_handler() -> impl axum::response::IntoResponse {
    let html = include_str!("../web/index.html");
    hyper::Response::builder()
        .status(hyper::StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(axum::body::Body::from(html))
        .unwrap()
}

