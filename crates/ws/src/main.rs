use anyhow::Error;
use std::env;
use tracing_subscriber;
use log::{error, info};

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::rt::{TokioIo, TokioExecutor};
use std::net::SocketAddr;
use std::sync::Arc;
use ws::WSServer;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Initialize tracing
    env_logger::init();
    
    //tracing_subscriber::fmt().init();

    // Get HTTP port from environment variable or use default
    let http_port = env::var("HTTP_PORT")
        .map(|port| port.parse::<u16>().unwrap_or(8083))
        .unwrap_or(8083);

    info!("Starting WebSocket server on port {}", http_port);

    // Create WebSocket server instance
    let server = WSServer::new();
    let server = Arc::new(server);

    // Create HTTP server with WebSocket upgrade support
    let addr = SocketAddr::from(([0, 0, 0, 0], http_port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    info!("Server listening on http://{}", addr);

    // Accept connections and handle them
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let server = server.clone();

        tokio::task::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| handle_request(req, server.clone()));

            let conn = ConnBuilder::new(TokioExecutor::new());
            let conn = conn.serve_connection_with_upgrades(io, service);

            if let Err(err) = conn.await {
                error!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    server: Arc<WSServer>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();

    if path == "/" {
        // Serve the HTML file
        let html_content = include_str!("../web/index.html");
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html")
            .body(Full::from(html_content))
            .unwrap())
    } else if path == "/ws" {
        // Handle WebSocket upgrade
        info!("New WebSocket connection handler started");
        ws::handle_websocket_upgrade(req, server).await
    } else {
        // Return 404 for other paths
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::from("Not Found"))
            .unwrap())
    }
}
