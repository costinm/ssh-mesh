#[cfg(feature = "test-utils")]
pub mod test_utils;

use anyhow::Context as AnyhowContext;
use log::{error, info};
use russh::keys::PrivateKey;
use russh::server;
use russh::server::Server;
use serde::Serialize;
use ssh_key;
use std::collections::HashMap;
#[allow(dead_code, unused)]
use std::{
    convert::Infallible,
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::SystemTime,
};
use tracing::{debug, instrument};
use tracing_subscriber::{EnvFilter, Registry, reload};

/// Global handle for dynamically reloading the tracing filter
pub static TRACING_RELOAD_HANDLE: std::sync::OnceLock<reload::Handle<EnvFilter, Registry>> =
    std::sync::OnceLock::new();

use utoipa::ToSchema;

// File paths for SSH authentication
pub mod auth;
pub mod handlers;
pub mod local_trace;
pub mod mux;
pub mod socks5;
pub mod sshc;
pub mod sshd;
pub mod sshmuxc;
pub mod utils;

pub use sshd::SshHandler;

// Configuration for the SSH server
#[derive(Clone)]
#[allow(unused)]
pub struct SshServer {
    keys: PrivateKey,
    clients: Arc<tokio::sync::Mutex<Vec<usize>>>,
    id_counter: Arc<std::sync::Mutex<usize>>,
    pub authorized_keys: Arc<Vec<crate::auth::AuthorizedKeyEntry>>,
    pub ca_keys: Arc<Vec<ssh_key::PublicKey>>,
    pub base_dir: PathBuf,
    /// Active SSH handlers indexed by their ID
    active_handlers:
        Arc<std::sync::Mutex<HashMap<usize, Arc<tokio::sync::Mutex<sshd::SshHandler>>>>>,
    /// Track connected clients with their remote forward listeners
    pub connected_clients: Arc<tokio::sync::Mutex<HashMap<usize, ConnectedClientInfo>>>,
    pub sftp_server_path: Option<String>,
    /// Root directory for built-in SFTP server (defaults to base_dir)
    pub sftp_root: PathBuf,
}

/// Information about a connected client
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ConnectedClientInfo {
    pub id: usize,
    pub user: String,
    pub comment: String,
    pub options: Option<String>,
    pub remote_forward_listeners: Vec<(String, u32)>,
    #[schema(value_type = String, format = DateTime)]
    pub connected_at: SystemTime,
}

#[derive(Clone)]
pub struct AppState {
    pub ssh_server: Arc<SshServer>,
    pub target_http_address: Option<String>,
    pub log_buffer: crate::local_trace::LogBuffer,
    pub ssh_client_manager: Arc<sshc::SshClientManager>,
}

// TODO: move the env vars to main

impl SshServer {
    /// Create a new SshServer instance with an optional private key
    /// If no key is provided, attempts to load from baseDir/.ssh/id_ed25519 or generates a new one
    ///
    /// # Arguments
    /// * `id` - Server ID
    /// * `key` - Optional private key
    /// * `base_dir` - Base directory containing the .ssh subdirectory
    /// * `sftp_server_path` - Optional path to external sftp-server binary
    /// * `sftp_root` - Optional root directory for built-in SFTP server (defaults to base_dir)
    pub fn new(
        id: usize,
        key: Option<PrivateKey>,
        base_dir: PathBuf,
        sftp_server_path: Option<String>,
        sftp_root: Option<PathBuf>,
    ) -> Self {
        let keys = match key {
            Some(key) => key,
            None => crate::auth::load_or_generate_keys_save(&base_dir),
        };

        // Load authorized keys
        let authorized_keys = match crate::auth::load_authorized_keys(&base_dir) {
            Ok(keys) => {
                info!("Loaded {} authorized keys", keys.len());
                Arc::new(keys)
            }
            Err(e) => {
                error!("Failed to load authorized_keys: {}", e);
                Arc::new(Vec::new())
            }
        };

        // Load CA keys
        let ca_keys = match crate::auth::load_authorized_cas(&base_dir) {
            Ok(cas) => {
                info!("Loaded {} CA keys", cas.len());
                Arc::new(cas)
            }
            Err(e) => {
                error!("Failed to load authorized_cas: {}", e);
                Arc::new(Vec::new())
            }
        };

        SshServer {
            keys,
            clients: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            id_counter: Arc::new(std::sync::Mutex::new(id)),
            authorized_keys,
            ca_keys,
            base_dir: base_dir.clone(),
            active_handlers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            connected_clients: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            sftp_server_path,
            sftp_root: sftp_root.unwrap_or(base_dir),
        }
    }

    pub fn get_config(&self) -> server::Config {
        let mut config = server::Config::default();
        config.keys.push(self.keys.clone());
        config.max_auth_attempts = 3;
        config.server_id = russh::SshId::Standard(String::from("SSH-2.0-Rust-SSH-Server"));
        config
    }

    /// Get a reference to the server's private key.
    pub fn private_key(&self) -> &PrivateKey {
        &self.keys
    }
}

impl server::Server for SshServer {
    type Handler = SshHandler;

    #[instrument(skip(self))]
    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        let mut id = self.id_counter.lock().unwrap();
        *id += 1;
        let handler = SshHandler::new(*id, self.clone());

        // Store the handler in active_handlers
        let handler_arc = Arc::new(tokio::sync::Mutex::new(handler.clone()));
        let mut active_handlers = self.active_handlers.lock().unwrap();
        active_handlers.insert(*id, handler_arc);

        handler
    }
}

// Function to start the SSH server
#[instrument(skip(config, server), fields(port = port))]
pub async fn run_ssh_server(
    port: u16,
    config: server::Config,
    server: SshServer,
) -> Result<(), anyhow::Error> {
    let addr = format!("0.0.0.0:{}", port);
    info!("Starting SSH server on {}", addr);

    let config = Arc::new(config);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    loop {
        debug!("Waiting for new connection...");
        let (stream, peer_addr) = listener.accept().await?;
        info!("Accepted connection from {:?}", peer_addr);
        let config = config.clone();
        let mut server_clone = server.clone();

        tokio::spawn(async move {
            let handler = server_clone.new_client(Some(peer_addr));
            let handler_id = handler.id;

            debug!("Starting session for handler {}", handler_id);

            match russh::server::run_stream(config, stream, handler).await {
                Ok(session) => {
                    info!("SSH session stream started for handler {}", handler_id);
                    // Drive the session to completion
                    if let Err(e) = session.await {
                        error!("SSH session error for handler {}: {:?}", handler_id, e);
                    }
                    info!("SSH session future finished for handler {}", handler_id);
                }
                Err(e) => {
                    error!("SSH handshake failed for handler {}: {}", handler_id, e);
                }
            }

            // Explicit cleanup after session ends (for any reason: disconnect, kill, error)
            let mut clients = server_clone.connected_clients.lock().await;
            if clients.remove(&handler_id).is_some() {
                debug!("Removed client {} from connected_clients", handler_id);
            }
        });
    }
}

/// Configuration for executing a command.
pub struct ExecConfig {
    pub args: Vec<String>,
    pub uid: u32,
}

/// Executes a command as a specific user.
pub fn run_exec_command(config: ExecConfig) -> Result<(), anyhow::Error> {
    let uid_val = config.uid;
    let args = config.args;

    info!("Executing command as user {}: {:?}", uid_val, args);

    #[cfg(unix)]
    {
        use nix::unistd::{Uid, setuid};
        // Drop privileges to the target user
        setuid(Uid::from_raw(uid_val)).context(
            "Failed to setuid - make sure you're running as root if you want to change users",
        )?;
    }

    let mut child = std::process::Command::new(&args[0])
        .args(&args[1..])
        .spawn()
        .context("Failed to spawn command")?;

    let status = child.wait().context("Failed to wait for command")?;

    if !status.success() {
        error!("Command exited with status: {:?}", status);
        if let Some(code) = status.code() {
            std::process::exit(code);
        } else {
            std::process::exit(1);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    #[test]
    fn test_ssh_server_creation() {
        let temp_dir = tempfile::Builder::new()
            .prefix("ssh_server_test")
            .tempdir()
            .expect("Failed to create temp dir");
        let base_dir = temp_dir.path().to_path_buf();

        let key = PrivateKey::random(&mut rand::rngs::OsRng, russh::keys::Algorithm::Ed25519)
            .expect("Failed to generate test key");
        let server = SshServer::new(42, Some(key), base_dir, None, None);
        let config = server.get_config();

        // Verify some configuration settings
        assert_eq!(config.keys.len(), 1);
        match &config.server_id {
            russh::SshId::Standard(id) => assert_eq!(id, "SSH-2.0-Rust-SSH-Server"),
            _ => panic!("Unexpected server ID format"),
        }
    }
}
