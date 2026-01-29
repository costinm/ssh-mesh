use futures_util::{SinkExt, StreamExt};
use std::env;
use std::process;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use url::Url;

/// wst is a minimal TCP tunnel over WebSockets, forwarding stdin/stdout.
async fn handle_stdio(
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("WST STARTING");
    let args: Vec<String> = env::args().collect();
    eprintln!("WST ARGS: {:?}", args);
    if args.len() < 2 {
        eprintln!("Usage: {} <URL>", args[0]);
        process::exit(1);
    }

    let token = env::var("TUN_TOKEN").ok();
    handle_stdio(&args[1], token).await?;

    Ok(())
}
