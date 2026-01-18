use anyhow::Error;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
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

    info!("Starting WebSocket server on port {}", http_port);

    let server = WSServer::new();
    let server = Arc::new(server);

    let html_content = include_str!("../web/index.html");
    let html_content = html_content.to_string();

    server
        .add_handler(
            "/".to_string(),
            move |_req: Request<Incoming>, _server: Arc<WSServer>| {
                let html = html_content.clone();
                Box::pin(async move {
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/html")
                        .body(Full::from(html))
                        .unwrap())
                })
            },
        )
        .await;

    server
        .add_handler(
            "/ws".to_string(),
            |req: Request<Incoming>, server: Arc<WSServer>| {
                Box::pin(async move { ws::handle_websocket_upgrade(req, server).await })
            },
        )
        .await;

    server
        .add_handler(
            "/api/clients".to_string(),
            |req: Request<Incoming>, server: Arc<WSServer>| {
                Box::pin(async move { ws::handle_list_clients(req, server).await })
            },
        )
        .await;

    server
        .add_handler(
            "/api/clients/".to_string(),
            |req: Request<Incoming>, server: Arc<WSServer>| {
                Box::pin(async move {
                    let method = req.method().clone();
                    let path = req.uri().path();

                    if method == Method::DELETE && path.starts_with("/api/clients/") {
                        ws::handle_remove_client(req, server).await
                    } else if method == Method::POST && path.contains("/message") {
                        ws::handle_send_message(req, server).await
                    } else {
                        Ok(Response::builder()
                            .status(StatusCode::METHOD_NOT_ALLOWED)
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
            |req: Request<Incoming>, server: Arc<WSServer>| {
                Box::pin(async move { ws::handle_broadcast(req, server).await })
            },
        )
        .await;

    let _ = server.start(http_port).await;

    Ok(())
}
