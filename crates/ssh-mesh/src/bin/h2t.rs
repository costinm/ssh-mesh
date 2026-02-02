use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::{Method, Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::env;
use std::process;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use url::Url;

/// h2t is a minimal TCP tunnel supporting multiple transports:
/// - Unix Domain Sockets (UDS): if argument starts with "/" or ":"
/// - WebSocket: if argument starts with "ws://" or "wss://"
/// - HTTP/2 (H2C/H2): if argument starts with "http://" or "https://"
/// - Default: generates HTTPS URL like "https://{arg}/_ssh"
///
/// Usage with SSH ProxyCommand:
///   `ssh -o ProxyCommand="h2t /tmp/ssh-mesh.sock" user@host`
///   `ssh -o ProxyCommand="h2t ws://localhost:8080/_ws" user@host`
///   `ssh -o ProxyCommand="h2t http://localhost:8081/_ssh" user@host`
///   `ssh -o ProxyCommand="h2t %h" user@host`

async fn handle_uds(path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let stream = UnixStream::connect(path).await?;
    let (mut read, mut write) = tokio::io::split(stream);

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let stdin_to_uds = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        loop {
            match stdin.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if write.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                    if write.flush().await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from stdin: {}", e);
                    break;
                }
            }
        }
    });

    let uds_to_stdout = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        loop {
            match read.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if stdout.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                    if stdout.flush().await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from UDS: {}", e);
                    break;
                }
            }
        }
    });

    tokio::select! {
        _ = stdin_to_uds => {}
        _ = uds_to_stdout => {}
    }

    Ok(())
}

async fn handle_websocket(
    url_str: &str,
    token: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = if url_str.contains("://") {
        Url::parse(url_str)?
    } else {
        Url::parse(&format!("ws://{}", url_str))?
    };

    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = url.as_str().into_client_request()?;

    if let Some(token) = token {
        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {}", token).parse().unwrap(),
        );
    }

    eprintln!("Connecting to {}", request.uri());

    // Check TCP first
    let host = request.uri().host().unwrap_or("127.0.0.1");
    let port = request.uri().port_u16().unwrap_or(80);
    match tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await {
        Ok(_) => eprintln!("TCP connection successful"),
        Err(e) => {
            eprintln!("TCP connection failed: {}", e);
            return Err(e.into());
        }
    }

    let (ws_stream, _): (
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        _,
    ) = match tokio::time::timeout(Duration::from_secs(10), connect_async(request)).await {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => {
            eprintln!("Failed to connect: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            eprintln!("Connection timeout during WebSocket handshake");
            return Err("Timeout".into());
        }
    };
    eprintln!("Connected to WebSocket");

    let (mut write, mut read) = ws_stream.split();

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let stdin_to_ws = tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        loop {
            match stdin.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if write
                        .send(Message::Binary(buffer[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = write.close().await;
    });

    let ws_to_stdout = tokio::spawn(async move {
        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    if stdout.write_all(&data).await.is_err() {
                        break;
                    }
                    if stdout.flush().await.is_err() {
                        break;
                    }
                }
                Ok(Message::Text(data)) => {
                    if stdout.write_all(data.as_bytes()).await.is_err() {
                        break;
                    }
                    if stdout.flush().await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) => break,
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = stdin_to_ws => {}
        _ = ws_to_stdout => {}
    }

    Ok(())
}

async fn handle_h2(
    url: &str,
    token: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create HTTP client
    let mut https_connector = HttpConnector::new();
    https_connector.enforce_http(false);

    let client = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build(https_connector);

    // Format URL
    let full_url = if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{}/_m/_ssh", url)
    };

    let uri = Uri::from_str(&full_url)?;

    // Create a channel for sending body chunks
    let (tx, rx) =
        mpsc::channel::<Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>>(10);

    // Create a stream body from the receiver
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = StreamBody::new(stream);

    // Build request
    let mut req_builder = Request::builder()
        .method(Method::POST)
        .uri(&uri)
        .header("x-host", "localhost:15022"); // TODO: Make configurable

    if let Some(token) = token {
        req_builder = req_builder.header("authorization", format!("Bearer {}", token));
    }

    let request = req_builder.body(body)?;

    // Spawn a task to read from stdin and send to the channel
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buffer = [0u8; 8192];

        loop {
            match stdin.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    let data = Bytes::copy_from_slice(&buffer[..n]);
                    if tx.send(Ok(Frame::data(data))).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from stdin: {}", e);
                    let _ = tx.send(Err(e.into())).await;
                    break;
                }
            }
        }
    });

    // Send request and get response
    let mut response = client.request(request).await?;

    if response.status().as_u16() != 200 {
        eprintln!("HTTP error: {}", response.status());
        return Err("HTTP request failed".into());
    }

    // Read response body and write to stdout
    let mut stdout = tokio::io::stdout();
    while let Some(frame) = response.body_mut().frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    stdout.write_all(&data).await?;
                    stdout.flush().await?;
                }
            }
            Err(e) => {
                eprintln!("Error reading response body: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Detect transport type from the argument
enum Transport {
    Uds,
    WebSocket,
    H2,
}

fn detect_transport(arg: &str) -> Transport {
    if arg.starts_with('/') || arg.starts_with(':') {
        Transport::Uds
    } else if arg.starts_with("ws://") || arg.starts_with("wss://") {
        Transport::WebSocket
    } else if arg.starts_with("http://") || arg.starts_with("https://") {
        Transport::H2
    } else {
        // Default: generate HTTPS URL
        Transport::H2
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <TARGET>", args[0]);
        eprintln!();
        eprintln!("TARGET formats:");
        eprintln!("  /path/to/socket   - Unix Domain Socket");
        eprintln!("  :path/to/socket   - Unix Domain Socket (abstract)");
        eprintln!("  ws://host/path    - WebSocket");
        eprintln!("  wss://host/path   - WebSocket (TLS)");
        eprintln!("  http://host/path  - HTTP/2 (H2C)");
        eprintln!("  https://host/path - HTTP/2 (H2)");
        eprintln!("  hostname          - HTTPS (generates https://hostname/_m/_ssh)");
        process::exit(1);
    }

    let target = &args[1];
    let token = env::var("TUN_TOKEN").ok();

    match detect_transport(target) {
        Transport::Uds => handle_uds(target).await?,
        Transport::WebSocket => handle_websocket(target, token).await?,
        Transport::H2 => handle_h2(target, token).await?,
    }

    Ok(())
}
