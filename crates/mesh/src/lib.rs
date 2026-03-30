pub mod local_trace;
pub mod uds;

use axum::serve;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

/// Configuration for a mesh application
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MeshConfig {
    /// Optional TCP port for HTTP server
    pub http_port: Option<u16>,
    /// Optional UDS path for HTTP/H2C server
    pub http_uds_path: Option<String>,
    /// Authorized UID for UDS connections
    pub auth_uid: Option<u32>,
}

/// A handler trait or structure for incoming generic JSON lines.
/// Typically implemented by the user of the library.
#[async_trait::async_trait]
pub trait LineHandler: Send + Sync + 'static {
    async fn handle_line(&self, line: &str) -> Result<Option<String>, anyhow::Error>;
}

/// Mesh application builder and runner
pub struct MeshApp {
    config: MeshConfig,
    router: Option<axum::Router>,
}

impl MeshApp {
    /// Create a new MeshApp instance
    pub fn new(config: MeshConfig) -> Self {
        Self {
            config,
            router: None,
        }
    }

    /// Set the HTTP router for the application
    pub fn with_router(mut self, router: axum::Router) -> Self {
        self.router = Some(router);
        self
    }

    /// Run the HTTP/H2C over TCP server
    pub async fn run_tcp_server(&self) -> Result<(), anyhow::Error> {
        if let Some(router) = &self.router {
            let uid = unsafe { libc::getuid() };
            // Fallback default port logic similar to pmond if not specified
            let port = self.config.http_port.unwrap_or(if uid == 0 {
                8081
            } else {
                8082 + (uid as u16 - 1000)
            });

            let addr = format!("127.0.0.1:{}", port);
            let listener = TcpListener::bind(&addr).await?;
            info!("MeshApp HTTP listening on http://{}", addr);

            serve(listener, router.clone().into_make_service()).await?;
        } else {
            error!("MeshApp: No router configured for TCP server");
        }
        Ok(())
    }

    /// Run the HTTP server on UDS socket using the extracted logic
    pub async fn run_uds_server(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(router) = &self.router {
            let path_str = if let Some(path) = &self.config.http_uds_path {
                path.clone()
            } else {
                let uid = unsafe { libc::getuid() };
                format!("/run/user/{}/pmond.sock", uid)
            };

            let path = std::path::PathBuf::from(&path_str);
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            let auth_uid = self.config.auth_uid;
            crate::uds::run_uds_server(router.clone(), &path_str, auth_uid).await?;
        } else {
            error!("MeshApp: No router configured for UDS server");
        }
        Ok(())
    }

    /// Parse JSON lines from stdin/stdout blockingly (often in separate task)
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
                break; // EOF
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            match handler.handle_line(trimmed).await {
                Ok(Some(response)) => {
                    stdout.write_all(response.as_bytes()).await?;
                    stdout.write_all(b"\n").await?;
                    stdout.flush().await?;
                }
                Ok(None) => {} // No response needed
                Err(e) => {
                    error!("MeshApp stdin handler error: {}", e);
                }
            }
        }
        Ok(())
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushClientMsg {
    Close,
    Ping,
    Other,
}

#[async_trait::async_trait]
pub trait PushSender: Send + 'static {
    async fn send_text(
        &mut self,
        text: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn recv(&mut self) -> Option<PushClientMsg>;
}

#[async_trait::async_trait]
pub trait PushHandler: Send + Sync + 'static {
    async fn handle_push(&self, sender: Box<dyn PushSender>);
}

/// Generic config provider trait. Implementations load config
/// objects by kind (category/subdirectory) and name (identifier/filename).
#[async_trait::async_trait]
pub trait ConfigProvider: Send + Sync {
    /// Load a config value as a JSON Value by kind and name.
    /// Returns None if the config does not exist.
    async fn get(&self, kind: &str, name: &str) -> Option<serde_json::Value>;
}
