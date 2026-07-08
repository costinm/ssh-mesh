pub mod auth;
pub mod config;
pub mod jobs;
pub mod jsonl;
pub mod local_trace;
pub mod message;
pub mod paths;
pub mod protocol;
pub mod server;
pub mod tun;

use std::sync::Arc;

/// A handler trait or structure for incoming lines-based protocol, usually json.
/// Typically implemented by the user of the library.
#[async_trait::async_trait]
pub trait LineHandler: Send + Sync + 'static {
    async fn handle_line(&self, line: &str) -> Result<Option<String>, anyhow::Error>;
}

/// Parse JSON lines from stdin/stdout.
pub async fn run_stdin_loop<H: LineHandler>(handler: Arc<H>) -> Result<(), anyhow::Error> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = tokio::io::BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(response) = handler.handle_line(trimmed).await? {
            stdout.write_all(response.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

/// Trait for handling an incoming generic stream (e.g. from a WebSocket).
#[async_trait::async_trait]
pub trait StreamHandler: Send + Sync + 'static {
    /// Handle the bridged stream.
    /// `dest` is the path/destination from the request.
    /// `headers` are key-value pairs from HTTP request headers.
    async fn handle(
        &self,
        dest: &str,
        headers: &std::collections::HashMap<String, String>,
        stream: tokio::io::DuplexStream,
    );
}

/// Trait to define the route for a handler.
pub trait Routable {
    fn route(&self) -> &str;
}

/// Generic config provider trait. Implementations load config
/// objects by kind (category/subdirectory) and name (identifier/filename).
#[async_trait::async_trait]
pub trait ConfigProvider: Send + Sync {
    /// Load a config value as a JSON Value by kind and name.
    /// Returns None if the config does not exist.
    async fn get(&self, kind: &str, name: &str) -> Option<serde_json::Value>;
}
