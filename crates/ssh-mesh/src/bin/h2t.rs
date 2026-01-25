use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::{Method, Request, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::env;
use std::process;
use std::str::FromStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// h2t is a minimal TCP tunnel over h2 (like Istio Ambient), forwarding stdin/stdout or creating a local listener
/// and forwarding all requests.
///
/// On the server, it expects a /ssh h2 handler that runs a SSH server connection
/// on the H2 in/out.
///
/// On client - use with 'ProxyCommand':
///   `ssh -o ProxyCommand="h2t %h"  user@host`
///
/// For testing, something like:
///  `ssh -o ProxyCommand="h2t http://localhost:8081/_ssh %h"  -o StrictHostKeyChecking=no	-o UserKnownHostsFile=/dev/null user@host`
///
/// Unfortunately Curl (AFAIK) doesn't support 2-way streaming with H2 -
/// if it did this program wouldn't be needed.
///

/// Stripped binary size should be 17 -> ~1.5M
/// Tracing is 10M -> 1.5M

async fn handle_stdio(url: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        format!("http://{}", url)
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

    if let Ok(token) = env::var("TUN_TOKEN") {
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

    //eprintln!("Connected: {}", response.status());
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

#[tokio::main(flavor = "multi_thread")]
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
