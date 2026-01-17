use clap::Parser;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Method, Request, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::env;
use std::process;
use std::str::FromStr;
use tokio::io::AsyncWriteExt;

/// h2t is a minimal TCP tunnel over h2 (like Istio Ambient), forwarding stdin/stdout or creating a local listener
/// and forwarding all requests.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Token to use for authentication
    #[clap(short, long, default_value = "")]
    token: String,

    /// URL or hostname to connect to
    #[clap(value_name = "URL")]
    url: String,
}

// Simple token source implementation (similar to TokenExec in Go)
struct TokenSource {
    command: String,
    args: Vec<String>,
}

impl TokenSource {
    fn new() -> Self {
        Self {
            command: "gcloud".to_string(),
            args: vec![
                "auth".to_string(),
                "print-access-token".to_string(),
                "--audience".to_string(),
            ],
        }
    }

    // Simplified token getter - in a real implementation this would execute commands
    fn get_token(
        &self,
        _audience: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // This is a placeholder - in a real implementation we would execute:
        // gcloud auth print-access-token --audience <audience>
        Ok("".to_string())
    }
}

async fn handle_tcp_connection(
    url: &str,
    token_source: &TokenSource,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create HTTP client
    let https_connector = HttpConnector::new();
    let client: Client<_, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(https_connector);

    // Format URL
    let full_url = if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    };

    let uri = Uri::from_str(&full_url)?;

    // Get token
    let token = token_source.get_token(&full_url)?;

    // Build request
    let mut req_builder = Request::builder()
        .method(Method::POST)
        .uri(&uri)
        .header("x-host", "localhost:15022");

    if !token.is_empty() {
        req_builder = req_builder.header("authorization", format!("Bearer {}", token));
    }

    let request = req_builder.body(Full::<Bytes>::new(Bytes::new()))?;

    // Send request and get response
    let response = client.request(request).await?;

    if response.status().as_u16() != 200 {
        eprintln!("HTTP error: {}", response.status());
        return Err("HTTP request failed".into());
    }

    println!("Connected to {} via TCP tunnel", full_url);

    // In a full implementation, we would set up bidirectional streaming here
    // between stdin/stdout and the HTTP response body

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    // Check if we have a URL argument
    if args.url.is_empty() {
        eprintln!("Error: URL argument is required");
        process::exit(1);
    }

    // Check if H2T_PORT environment variable is set for listener mode
    if let Ok(port) = env::var("H2T_PORT") {
        if !port.is_empty() {
            println!("Starting listener on port {}", port);

            let listener = tokio::net::TcpListener::bind(&format!("0.0.0.0:{}", port)).await?;

            let token_source = TokenSource::new();

            loop {
                match listener.accept().await {
                    Ok((mut socket, _addr)) => {
                        let url = args.url.clone();
                        let _token_source = token_source.clone();

                        // Handle connection in a separate task
                        tokio::spawn(async move {
                            println!("Accepted connection, tunneling to {}", url);

                            // In a full implementation, we would establish the HTTP tunnel here
                            // and forward data between the TCP socket and the HTTP stream

                            // For now, just close the connection
                            let _ = socket
                                .write_all(b"HTTP tunnel not fully implemented\n")
                                .await;
                        });
                    }
                    Err(e) => {
                        eprintln!("Error accepting connection: {}", e);
                    }
                }
            }
        }
    }

    // Stdin/stdout mode
    let token_source = TokenSource::new();
    handle_tcp_connection(&args.url, &token_source).await?;

    Ok(())
}

// Required trait implementations
impl Clone for TokenSource {
    fn clone(&self) -> Self {
        Self {
            command: self.command.clone(),
            args: self.args.clone(),
        }
    }
}
