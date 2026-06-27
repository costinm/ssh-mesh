pub mod auth;
pub mod config;
pub mod jobs;
pub mod local_trace;
pub mod protocol;
pub mod server;
pub mod tun;

use anyhow::Context;
use axum::serve;
use serde::{Deserialize, Serialize};
use std::os::fd::FromRawFd;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

/// Configuration for a mesh application
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MeshConfig {
    /// Authorization config for UDS connections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<auth::AuthConfig>,
    /// Optional TCP port for HTTP server
    /// By default only a default control UDS socket is exposed, accepting JSON
    /// messages - as well as 'inetd' and 'xinetd' modes for use with mesh-init or
    /// other compatible 'activation' services.
    /// If specified, this will configure H2C server on this port.
    pub http_port: Option<u16>,
    /// Optional UDS path for HTTP/H2C server
    pub http_uds_path: Option<String>,
}

/// A handler trait or structure for incoming lines-based protocol, usually json.
/// Typically implemented by the user of the library.
#[async_trait::async_trait]
pub trait LineHandler: Send + Sync + 'static {
    async fn handle_line(&self, line: &str) -> Result<Option<String>, anyhow::Error>;
}

/// Mesh application builder and runner
pub struct MeshApp {
    config: MeshConfig,
    /// Optional Axum router for HTTP/H2C server.
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
            // Check for socket activation via LISTEN_FD
            let listener = if let Ok(fd_str) = std::env::var("LISTEN_FD") {
                if let Ok(fd) = fd_str.parse::<i32>() {
                    info!("MeshApp: Using activated listener FD {}", fd);
                    let std_listener = activated_tcp_listener(fd)?;
                    std_listener.set_nonblocking(true)?;
                    TcpListener::from_std(std_listener)?
                } else {
                    self.bind_default_tcp().await?
                }
            } else {
                self.bind_default_tcp().await?
            };

            serve(listener, router.clone().into_make_service()).await?;
        } else {
            error!("MeshApp: No router configured for TCP server");
        }
        Ok(())
    }

    /// Bind the default TCP port.
    async fn bind_default_tcp(&self) -> Result<TcpListener, anyhow::Error> {
        // SAFETY: getuid has no preconditions and does not access Rust-managed memory.
        let uid = unsafe { libc::getuid() };
        let port = self
            .config
            .http_port
            .unwrap_or_else(|| default_http_port_for_uid(uid));

        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await?;
        info!("MeshApp HTTP listening on http://{}", addr);
        Ok(listener)
    }

    /// Run the HTTP server on UDS socket using the extracted logic
    pub async fn run_uds_server(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(router) = &self.router {
            let current_exe = std::env::current_exe()?;
            let app = current_exe
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();

            let listen_path = self
                .config
                .http_uds_path
                .as_deref()
                .unwrap_or("control.sock");

            crate::server::run_axum_server(&app, Some(listen_path), router.clone()).await?;
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

fn default_http_port_for_uid(uid: libc::uid_t) -> u16 {
    if uid == 0 {
        return 8081;
    }

    let offset = uid.saturating_sub(1000).min(u16::MAX as libc::uid_t - 8082);
    8082 + offset as u16
}

fn activated_tcp_listener(fd: i32) -> Result<std::net::TcpListener, anyhow::Error> {
    validate_tcp_listener_fd(fd)?;
    // SAFETY: validate_tcp_listener_fd verifies that fd is an open TCP listener
    // socket. from_raw_fd takes ownership exactly once in this activation path.
    Ok(unsafe { std::net::TcpListener::from_raw_fd(fd) })
}

fn validate_tcp_listener_fd(fd: i32) -> Result<(), anyhow::Error> {
    let mut socket_type: libc::c_int = 0;
    let mut socket_type_len = std::mem::size_of_val(&socket_type) as libc::socklen_t;
    // SAFETY: socket_type points to writable memory of socket_type_len bytes.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut socket_type_len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("LISTEN_FD is not a socket");
    }
    if socket_type != libc::SOCK_STREAM {
        anyhow::bail!("LISTEN_FD is not a stream socket");
    }

    // SAFETY: sockaddr_storage is a plain old data buffer initialized by getsockname.
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut addr_len = std::mem::size_of_val(&addr) as libc::socklen_t;
    // SAFETY: addr points to writable storage large enough for addr_len bytes.
    let rc = unsafe {
        libc::getsockname(
            fd,
            (&mut addr as *mut libc::sockaddr_storage).cast(),
            &mut addr_len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("LISTEN_FD has no socket address");
    }
    if addr.ss_family as libc::c_int != libc::AF_INET
        && addr.ss_family as libc::c_int != libc::AF_INET6
    {
        anyhow::bail!("LISTEN_FD is not an IPv4 or IPv6 socket");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::default_http_port_for_uid;

    #[test]
    fn default_http_port_handles_root_and_small_uids() {
        assert_eq!(default_http_port_for_uid(0), 8081);
        assert_eq!(default_http_port_for_uid(1), 8082);
        assert_eq!(default_http_port_for_uid(999), 8082);
        assert_eq!(default_http_port_for_uid(1000), 8082);
    }

    #[test]
    fn default_http_port_caps_large_uids() {
        assert_eq!(default_http_port_for_uid(1001), 8083);
        assert_eq!(default_http_port_for_uid(u32::MAX), u16::MAX);
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

/// Generic config provider trait. Implementations load config
/// objects by kind (category/subdirectory) and name (identifier/filename).
#[async_trait::async_trait]
pub trait ConfigProvider: Send + Sync {
    /// Load a config value as a JSON Value by kind and name.
    /// Returns None if the config does not exist.
    async fn get(&self, kind: &str, name: &str) -> Option<serde_json::Value>;
}
