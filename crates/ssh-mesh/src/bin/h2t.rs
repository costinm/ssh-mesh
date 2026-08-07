use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioExecutor;
use std::env;
use std::fs::OpenOptions;
use std::process;
use std::str::FromStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::error;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
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
                    error!("Error reading from stdin: {}", e);
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
                    error!("Error reading from UDS: {}", e);
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

    eprintln!("[h2t] Connecting WebSocket to {}", request.uri());

    let host = request.uri().host().unwrap_or("127.0.0.1").to_string();
    let is_wss = request.uri().scheme_str() == Some("wss") || request.uri().scheme_str() == Some("https");
    let port = request.uri().port_u16().unwrap_or(if is_wss { 443 } else { 80 });

    let tcp_stream = connect_tcp_stream(&host, port).await?;

    let maybe_tls = if is_wss {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())?;
        let tls_stream = connector.connect(server_name, tcp_stream).await?;
        tokio_tungstenite::MaybeTlsStream::Rustls(tls_stream)
    } else {
        tokio_tungstenite::MaybeTlsStream::Plain(tcp_stream)
    };

    let (ws_stream, _) = tokio_tungstenite::client_async(request, maybe_tls).await?;

    eprintln!("[h2t] Connected to WebSocket");

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

enum H2Stream {
    Tcp(tokio::net::TcpStream),
    Tls(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
}

impl tokio::io::AsyncRead for H2Stream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            H2Stream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            H2Stream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for H2Stream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            H2Stream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            H2Stream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            H2Stream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            H2Stream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            H2Stream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            H2Stream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

async fn connect_tcp_stream(host: &str, port: u16) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let addrs: Vec<_> = tokio::net::lookup_host(format!("{}:{}", host, port)).await?.collect();
    let mut sorted_addrs = addrs.clone();
    sorted_addrs.sort_by_key(|addr| if addr.is_ipv4() { 0 } else { 1 });

    for addr in sorted_addrs {
        eprintln!("[h2t] Trying connection to {}", addr);
        if let Ok(stream) = tokio::net::TcpStream::connect(addr).await {
            return Ok(stream);
        }
    }

    Err("Failed to connect to any resolved IP address".into())
}

async fn handle_h2(
    url: &str,
    token: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let full_url = if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{}/_m/_ssh", url)
    };

    let uri = Uri::from_str(&full_url)?;
    let host = uri.host().ok_or("missing host in URI")?;
    let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("https") { 443 } else { 80 });

    let tcp_stream = connect_tcp_stream(host, port).await?;

    let stream = if uri.scheme_str() == Some("https") {
        eprintln!("[h2t] Initiating TLS handshake with ALPN h2 for {}", host);
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];

        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())?;
        let tls_stream = connector.connect(server_name, tcp_stream).await?;
        H2Stream::Tls(tls_stream)
    } else {
        H2Stream::Tcp(tcp_stream)
    };

    eprintln!("[h2t] Performing HTTP/2 handshake...");
    let io_stream = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), io_stream).await?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            eprintln!("[h2t] HTTP/2 connection error: {:?}", err);
        }
    });

    // Create a channel for sending body chunks
    let (tx, rx) =
        mpsc::channel::<Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>>(10);

    // Create a stream body from the receiver
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = StreamBody::new(stream);


    // Build request (Hyper derives :method, :scheme, :authority, and :path from full URI)
    let mut req_builder = Request::builder()
        .method(Method::POST)
        .uri(&uri)
        .header("x-host", "localhost:15022");

    if let Some(token) = token {
        req_builder = req_builder.header("authorization", format!("Bearer {}", token));
    }

    // Read the exact client SSH identification string from stdin if available (or use OpenSSH default)
    let mut stdin = tokio::io::stdin();
    let mut banner_buf = Vec::new();
    let mut byte = [0u8; 1];
    while let Ok(1) = tokio::time::timeout(std::time::Duration::from_millis(100), stdin.read(&mut byte)).await.unwrap_or(Ok(0)) {
        banner_buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }

    let client_banner = if !banner_buf.is_empty() {
        Bytes::from(banner_buf)
    } else {
        Bytes::from_static(b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10\r\n")
    };

    // Synchronously send exact SSH identification string so Google Frontend flushes POST headers & data immediately
    let _ = tx.try_send(Ok(Frame::data(client_banner)));

    // Spawn a task to read remaining binary data from stdin and send to the channel
    tokio::spawn(async move {
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
                    eprintln!("[h2t] Error reading from stdin: {}", e);
                    let _ = tx.send(Err(e.into())).await;
                    break;
                }
            }
        }
    });

    let request = req_builder.body(body)?;

    eprintln!("[h2t] Sending POST request...");
    let mut response = sender.send_request(request).await?;
    eprintln!("[h2t] Response status: {}", response.status());

    if response.status().as_u16() != 200 {
        eprintln!("[h2t] HTTP error: {}", response.status());
        return Err("HTTP request failed".into());
    }

    // Read response body and write to stdout
    let mut stdout = tokio::io::stdout();
    while let Some(frame_res) = response.body_mut().frame().await {
        if let Ok(frame) = frame_res {
            if let Ok(data) = frame.into_data() {
                stdout.write_all(&data).await?;
                stdout.flush().await?;
            }
        }
    }

    if response.status().as_u16() != 200 {
        error!("HTTP error: {}", response.status());
        return Err("HTTP request failed".into());
    }

    // Read response body and write to stdout
    let mut stdout = tokio::io::stdout();
    while let Some(frame_res) = response.body_mut().frame().await {
        match frame_res {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    stdout.write_all(&data).await?;
                    stdout.flush().await?;
                }
            }
            Err(e) => {
                error!("Error reading response body: {}", e);
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

fn init_telemetry() {
    let filter = tracing_subscriber::EnvFilter::from_default_env();
    let log_path = env::var("MESH_LOG_FILE").unwrap_or_else(|_| {
        mesh::paths::AppPaths::for_app("h2t")
            .run_dir("h2t")
            .join("h2t.log")
            .to_string_lossy()
            .into_owned()
    });

    if let Some(parent) = std::path::Path::new(&log_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Ok(file) = OpenOptions::new().create(true).append(true).open(&log_path) {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(move || file.try_clone().expect("clone h2t log file"))
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::registry().with(filter).init();
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_telemetry();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        error!(
            "Usage: {} <TARGET>\n\
             TARGET formats:\n\
               /path/to/socket   - Unix Domain Socket\n\
               :path/to/socket   - Unix Domain Socket (abstract)\n\
               ws://host/path    - WebSocket\n\
               wss://host/path   - WebSocket (TLS)\n\
               http://host/path  - HTTP/2 (H2C)\n\
               https://host/path - HTTP/2 (H2)\n\
               hostname          - HTTPS (generates https://hostname/_m/_ssh)",
            args[0]
        );
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
