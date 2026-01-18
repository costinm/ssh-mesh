use crate::ProcMon;
use bytes::Bytes;
use fastwebsockets::{upgrade, Frame, OpCode, Payload, WebSocket};
use http_body_util::Full;
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{debug, error, info};
use std::path::Path;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

/// HTTP handler for /_ps endpoint - returns all processes as JSON
pub async fn handle_ps_request(
    _req: Request<Incoming>,
    proc_mon: Arc<ProcMon>,
) -> Result<Response<Full<bytes::Bytes>>, hyper::Error> {
    debug!("Received PS request");

    // Get all processes
    let processes = proc_mon.get_all_processes();

    // Convert to JSON
    let json_response = match serde_json::to_string(&processes) {
        Ok(json) => json,
        Err(e) => {
            let error_msg = format!(r#"{{"error": "Failed to serialize processes: {}"}}"#, e);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .body(Full::new(bytes::Bytes::from(error_msg)))
                .unwrap());
        }
    };

    // Return JSON response
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(bytes::Bytes::from(json_response)))
        .unwrap())
}

/// HTTP handler for / endpoint - serves the web interface
pub async fn handle_root_request(
    _req: Request<Incoming>,
) -> Result<Response<Full<bytes::Bytes>>, hyper::Error> {
    // Try to serve index.html from the web directory
    let web_path = Path::new("web/index.html");
    if let Ok(mut file) = File::open(web_path).await {
        let mut contents = Vec::new();
        if file.read_to_end(&mut contents).await.is_ok() {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/html")
                .body(Full::new(bytes::Bytes::from(contents)))
                .unwrap());
        }
    }

    // Fallback to simple text response
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(Full::new(bytes::Bytes::from(
            "<!DOCTYPE html>
            <html>
            <head><title>PMOND</title></head>
            <body>
                <h1>PMOND - Process Monitor</h1>
                <p><a href='/web/'>Web Interface</a></p>
                <p><a href='/_ps'>Process API</a></p>
                <p><a href='/ws'>WebSocket</a></p>
            </body>
            </html>",
        )))
        .unwrap())
}

/// Serve static files from the web directory
pub async fn handle_static_file(path: &str) -> Result<Response<Full<bytes::Bytes>>, hyper::Error> {
    // Security: prevent directory traversal
    if path.contains("..") {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(bytes::Bytes::from("Forbidden")))
            .unwrap());
    }

    // Construct file path
    let file_path = if path == "/" || path.is_empty() {
        "web/index.html"
    } else {
        &format!("web{}", path)
    };

    let web_path = Path::new(file_path);
    if let Ok(mut file) = File::open(web_path).await {
        // Determine content type based on file extension
        let content_type = match web_path.extension().and_then(|e| e.to_str()) {
            Some("html") => "text/html",
            Some("css") => "text/css",
            Some("js") => "application/javascript",
            Some("json") => "application/json",
            Some("png") => "image/png",
            Some("jpg") | Some("jpeg") => "image/jpeg",
            Some("gif") => "image/gif",
            Some("svg") => "image/svg+xml",
            _ => "application/octet-stream",
        };

        let mut contents = Vec::new();
        if file.read_to_end(&mut contents).await.is_ok() {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", content_type)
                .body(Full::new(bytes::Bytes::from(contents)))
                .unwrap());
        }
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(bytes::Bytes::from("File not found")))
        .unwrap())
}

/// WebSocket connection handler
pub async fn handle_websocket(
    ws: WebSocket<TokioIo<hyper::upgrade::Upgraded>>,
    proc_mon: Arc<ProcMon>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("New WebSocket connection handler started");
    let mut ws = ws;

    // Send initial process list
    info!("Attempting to send initial process list");
    let processes = proc_mon.get_all_processes();
    if let Ok(json_response) = serde_json::to_string(&processes) {
        let message = Frame::text(Payload::from(json_response.as_bytes()));
        if let Err(e) = ws.write_frame(message).await {
            error!("Failed to send initial process list: {}", e);
        } else {
            info!("Successfully sent initial process list");
        }
    } else {
        error!("Failed to serialize initial process list");
    }

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

    info!("Entering WebSocket event loop");
    loop {
        tokio::select! {
            // Handle incoming WebSocket messages (if any)
            msg = ws.read_frame() => {
                match msg {
                    Ok(frame) => {
                        match frame.opcode {
                            OpCode::Close => {
                                info!("Received close message");
                                break;
                            }
                            OpCode::Text => {
                                let text = String::from_utf8_lossy(&frame.payload);
                                debug!("Received WebSocket message: {}", text);
                                // Echo it back
                                let echo_message = Frame::text(Payload::from(text.as_bytes()));
                                if let Err(e) = ws.write_frame(echo_message).await {
                                    error!("Failed to send echo message: {}", e);
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        error!("WebSocket error: {}", e);
                        break;
                    }
                }
            }

            // Send periodic updates
            _ = interval.tick() => {
                info!("Sending periodic process update");
                let processes = proc_mon.get_all_processes();
                if let Ok(json_response) = serde_json::to_string(&processes) {
                    let message = Frame::text(Payload::from(json_response.as_bytes()));
                    if let Err(e) = ws.write_frame(message).await {
                        error!("Failed to send WebSocket update: {}", e);
                        break;
                    }
                }
            }
        }
    }
    info!("Exiting WebSocket event loop");
    Ok(())
}

/// Handle WebSocket upgrade requests
pub async fn handle_websocket_upgrade(
    mut req: Request<Incoming>,
    proc_mon: Arc<ProcMon>,
) -> Result<Response<Full<bytes::Bytes>>, hyper::Error> {
    debug!(
        "WebSocket request - Method: {}, URI: {}",
        req.method(),
        req.uri()
    );
    debug!("Headers: {:?}", req.headers());

    // Check if this is a WebSocket upgrade request
    if upgrade::is_upgrade_request(&req) {
        debug!("Attempting WebSocket upgrade");

        let (response, fut) = match upgrade::upgrade(&mut req) {
            Ok((response, fut)) => (response, fut),
            Err(_e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(bytes::Bytes::from("WebSocket upgrade failed")))
                    .unwrap());
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

            if let Err(e) = handle_websocket(ws, proc_mon).await {
                error!("Error in WebSocket connection: {}", e);
            }
        });

        debug!("After upgrade");
        // Convert the Empty body response to Full body
        let (parts, _body) = response.into_parts();
        let response = Response::from_parts(parts, Full::new(Bytes::new()));
        Ok(response)
    } else {
        Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(bytes::Bytes::from("Expected WebSocket upgrade")))
            .unwrap())
    }
}

/// Main HTTP service function that routes requests
pub async fn http_service(
    req: Request<Incoming>,
    proc_mon: Arc<ProcMon>,
) -> Result<Response<Full<bytes::Bytes>>, hyper::Error> {
    info!("Routing request: {} {}", req.method(), req.uri().path());
    match (req.method(), req.uri().path()) {
        (&hyper::Method::GET, "/") => handle_root_request(req).await,
        (&hyper::Method::GET, "/_ps") => handle_ps_request(req, proc_mon.clone()).await,
        (&hyper::Method::GET, "/ws") => handle_websocket_upgrade(req, proc_mon).await,
        (&hyper::Method::GET, "/ws2") => handle_websocket2_upgrade(req).await,
        (&hyper::Method::GET, path) if path.starts_with("/web/") => {
            let static_path = path.strip_prefix("/web").unwrap_or("/");
            handle_static_file(static_path).await
        }
        (&hyper::Method::GET, path) => handle_static_file(path).await,
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(bytes::Bytes::from("Not Found")))
            .unwrap()),
    }
}

/// Simple WebSocket connection handler
pub async fn handle_websocket2(
    ws: WebSocket<TokioIo<hyper::upgrade::Upgraded>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("New WebSocket connection handler for /ws2 started");
    let mut ws = ws;
    let msg = Frame::text(Payload::from("Hello from /ws2".as_bytes()));
    ws.write_frame(msg).await?;
    info!("/ws2 Sent hello message");
    Ok(())
}

/// Handle WebSocket upgrade requests for /ws2
pub async fn handle_websocket2_upgrade(
    mut req: Request<Incoming>,
) -> Result<Response<Full<bytes::Bytes>>, hyper::Error> {
    debug!("/ws2 WebSocket request");

    if upgrade::is_upgrade_request(&req) {
        debug!("Attempting WebSocket upgrade for /ws2");
        let (response, fut) = match upgrade::upgrade(&mut req) {
            Ok((response, fut)) => (response, fut),
            Err(e) => {
                error!("WebSocket upgrade error for /ws2: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(bytes::Bytes::from("WebSocket upgrade failed")))
                    .unwrap());
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
            if let Err(e) = handle_websocket2(ws).await {
                error!("Error in /ws2 WebSocket connection: {}", e);
            }
        });
        // Convert the Empty body response to Full body
        let (parts, _body) = response.into_parts();
        let response = Response::from_parts(parts, Full::new(Bytes::new()));
        Ok(response)
    } else {
        Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(bytes::Bytes::from("Expected WebSocket upgrade")))
            .unwrap())
    }
}
