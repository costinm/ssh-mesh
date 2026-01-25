use futures_util::{SinkExt, StreamExt};
use std::env;
use std::process;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use url::Url;

/// wst is a minimal TCP tunnel over WebSockets, forwarding stdin/stdout.
///
/// On client - use with 'ProxyCommand':
///   `ssh -o ProxyCommand="wst %h"  user@host`
///
/// For testing:
///  `ssh -o ProxyCommand="wst ws://localhost:15028/_ssh %h"  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@host`

async fn handle_stdio(url_str: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = if url_str.contains("://") {
        Url::parse(url_str)?
    } else {
        Url::parse(&format!("ws://{}", url_str))?
    };

    let mut request = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
        .uri(url.as_str())
        .header("Host", url.host_str().unwrap_or("localhost"));

    if let Ok(token) = env::var("TUN_TOKEN") {
        request = request.header("Authorization", format!("Bearer {}", token));
    }

    let request = request.body(())?;

    let (ws_stream, _) = connect_async(request).await?;
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
                Err(e) => {
                    eprintln!("Error reading from stdin: {}", e);
                    break;
                }
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
                Err(e) => {
                    eprintln!("Error reading from websocket: {}", e);
                    break;
                }
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
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <URL>", args[0]);
        process::exit(1);
    }

    handle_stdio(&args[1]).await?;

    Ok(())
}
