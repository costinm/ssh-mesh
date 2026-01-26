use axum::{
    body::Body,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{any, delete, get, post},
    Router,
};
use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use hyper::{Request, Response};
use log::{debug, info};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tracing::{error as tracing_error, instrument};
use russh::server::Server;

use crate::AppState;

pub fn app(app_state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/api/ssh/clients", get(get_ssh_clients))
        .route("/_ssh", any(handle_ssh_request))
        .route("/_ssh/*rest", any(handle_ssh_request))
        .route(
            "/ws",
            get(move |State(app_state): State<AppState>, req| {
                ws::handle_websocket_upgrade(State(app_state.ws_server), req)
            }),
        )
        .route(
            "/api/clients",
            get(move |State(app_state): State<AppState>| {
                ws::handle_list_clients(State(app_state.ws_server))
            }),
        )
        .route(
            "/api/clients/:id",
            delete(move |State(app_state): State<AppState>, path| {
                ws::handle_remove_client(State(app_state.ws_server), path)
            }),
        )
        .route(
            "/api/clients/:id/message",
            post(move |State(app_state): State<AppState>, path, json| {
                ws::handle_send_message(State(app_state.ws_server), path, json)
            }),
        )
        .route(
            "/api/broadcast",
            post(move |State(app_state): State<AppState>, json| {
                ws::handle_broadcast(State(app_state.ws_server), json)
            }),
        )
        .with_state(app_state)
}

async fn serve_index() -> impl IntoResponse {
    let html_content = tokio::fs::read_to_string("web/ssh.html").await.unwrap();
    Html(html_content)
}

async fn get_ssh_clients(State(app_state): State<AppState>) -> impl IntoResponse {
    let clients = app_state.ssh_server.connected_clients.lock().await;
    (StatusCode::OK, Json(clients.clone()))
}

// SSH handler for /_ssh* paths - handles SSH over HTTP/2
#[instrument(skip(req, state), fields(method = %req.method(), uri = %req.uri()))]
pub async fn handle_ssh_request(
    State(state): State<AppState>,
    req: Request<Body>,
) -> impl IntoResponse {
    info!("Received SSH request: {} {}", req.method(), req.uri());

    // Use shared SSH server
    // We clone the server to get a mutable instance (interior mutability handles state)
    // SshServer is designed to be cloned
    let mut ssh_server = state.ssh_server.as_ref().clone();
    let config = Arc::new(ssh_server.get_config());
    let handler = ssh_server.new_client(None);

    // Create a bidirectional stream adapter for HTTP/2 body
    let (reader_tx, reader_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(100);
    let (writer_tx, writer_rx) = mpsc::channel::<Bytes>(100);

    // Spawn task to read from HTTP request body and feed to SSH
    let body = req.into_body();
    tokio::spawn(async move {
        let mut body = body;
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if reader_tx.send(Ok(data)).await.is_err() {
                            break;
                        }
                    }
                }
                Some(Err(e)) => {
                    let _ = reader_tx
                        .send(Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Body read error: {}", e),
                        )))
                        .await;
                    break;
                }
                None => break,
            }
        }
    });

    // Create the bidirectional stream adapter
    let stream = Http2SshStream {
        reader: reader_rx,
        writer: writer_tx,
        read_buf: bytes::BytesMut::new(),
    };

    let handler_id = handler.id;
    let connected_clients = ssh_server.connected_clients.clone();

    // Run SSH over the HTTP/2 stream
    match russh::server::run_stream(config, stream, handler).await {
        Ok(session) => {
            info!("SSH session started successfully");

            // Spawn task to handle the SSH session
            tokio::spawn(async move {
                if let Err(e) = session.await {
                    tracing_error!("SSH session error: {:?}", e);
                }
                info!("SSH session completed");

                // Explicit cleanup after session ends
                let mut clients = connected_clients.lock().await;
                if clients.remove(&handler_id).is_some() {
                    debug!("Removed client {} from connected_clients", handler_id);
                }
            });

            // Create response body from writer_rx
            // Body::from_stream expects a stream of Bytes (Result<Bytes, Error>)
            let response_stream =
                tokio_stream::wrappers::ReceiverStream::new(writer_rx).map(Ok::<_, std::io::Error>);

            let response = Response::builder()
                .status(200)
                .body(Body::from_stream(response_stream))
                .unwrap();

            response
        }
        Err(e) => {
            tracing_error!("Failed to start SSH session: {:?}", e);
            let response = Response::builder()
                .status(500)
                .body(Body::from(format!("SSH session failed: {:?}", e)))
                .unwrap();
            response
        }
    }
}

// Adapter to bridge HTTP/2 body streams with AsyncRead + AsyncWrite
struct Http2SshStream {
    reader: mpsc::Receiver<Result<Bytes, std::io::Error>>,
    writer: mpsc::Sender<Bytes>,
    read_buf: bytes::BytesMut,
}

impl AsyncRead for Http2SshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If we have buffered data, use it first
        if !self.read_buf.is_empty() {
            let to_copy = buf.remaining().min(self.read_buf.len());
            buf.put_slice(&self.read_buf[..to_copy]);
            self.read_buf.advance(to_copy);
            return Poll::Ready(Ok(()));
        }

        // Try to receive more data
        match self.reader.poll_recv(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let to_copy = buf.remaining().min(data.len());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.read_buf.extend_from_slice(&data[to_copy..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Http2SshStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Try to send data through the channel
        let data = Bytes::copy_from_slice(buf);
        match self.writer.try_send(data) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel is full, register waker and return pending
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
