#[cfg(feature = "test-utils")]
pub mod test_utils;

use anyhow::Context as AnyhowContext;
use log::{error, info};
use russh::keys::PrivateKey;
use russh::server;
use russh::server::Server;
use serde::{Deserialize, Serialize};
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

/// Re-export the global tracing reload handle from mesh crate.
pub use mesh::local_trace::TRACING_RELOAD_HANDLE;

use utoipa::ToSchema;

// File paths for SSH authentication
pub mod auth;
pub mod config_provider;
pub mod handlers;
pub mod local_trace;
pub mod mux;
pub mod socks5;
pub mod sshc;
pub mod sshd;
pub mod sshmuxc;
pub mod utils;

pub use sshd::SshHandler;

/// Configurable fields for MeshNode, loadable from JSON or YAML.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MeshNodeConfig {
    pub base_dir: Option<PathBuf>,
    pub ssh_port: Option<u16>,
    pub http_port: Option<u16>,
    pub sftp_server_path: Option<String>,
    pub sftp_root: Option<PathBuf>,
    /// Optional list of authorized public keys (OpenSSH format lines).
    /// If present, these are used in addition to keys loaded from the
    /// `authorized_keys` file in base_dir.
    pub authorized_keys: Option<Vec<String>>,
    /// Optional list of CA public keys (OpenSSH format).
    /// If present, these are used in addition to CAs loaded from
    /// the `authorized_cas` file in base_dir.
    pub ca_keys: Option<Vec<String>>,
}

// MeshNode is the main server struct (formerly SshServer).
#[derive(Clone)]
#[allow(unused)]
pub struct MeshNode {
    pub cfg: MeshNodeConfig,

    keys: PrivateKey,
    clients: Arc<tokio::sync::Mutex<Vec<usize>>>,
    id_counter: Arc<std::sync::Mutex<usize>>,

    pub authorized_keys: Arc<Vec<crate::auth::AuthorizedKeyEntry>>,
    pub ca_keys: Arc<Vec<ssh_key::PublicKey>>,

    /// Active SSH handlers indexed by their ID
    active_handlers:
        Arc<std::sync::Mutex<HashMap<usize, Arc<tokio::sync::Mutex<sshd::SshHandler>>>>>,
    /// Track connected clients with their remote forward listeners
    pub connected_clients: Arc<tokio::sync::Mutex<HashMap<usize, ConnectedClientInfo>>>,
    pub server_handle: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
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
    pub ssh_server: Arc<MeshNode>,
    pub target_http_address: Option<String>,
    pub ssh_client_manager: Arc<sshc::SshClientManager>,
}

// TODO: move the env vars to main

impl MeshNode {
    /// Load a MeshNodeConfig from JSON or YAML files in the given directory using config-rs.
    /// Returns default if neither exists.
    pub fn load_config(base_dir: &Path) -> MeshNodeConfig {
        let mut builder = config::Config::builder();

        for ext in &["yaml", "json", "toml"] {
            let path = base_dir.join(format!("mesh.{}", ext));
            if path.exists() {
                builder = builder.add_source(config::File::from(path));
                break;
            }
        }

        match builder
            .build()
            .and_then(|c| c.try_deserialize::<MeshNodeConfig>())
        {
            Ok(cfg) => {
                info!("Loaded config from {:?}", base_dir);
                cfg
            }
            Err(_) => MeshNodeConfig::default(),
        }
    }

    /// Create a new MeshNode instance.
    ///
    /// # Arguments
    /// * `base_dir` - Optional base directory containing the .ssh subdirectory.
    ///   Defaults to cfg.base_dir, then current directory.
    /// * `cfg` - Optional configuration. If not provided, loads from
    ///   `mesh.yaml` or `mesh.json` in `base_dir`.
    pub fn new(base_dir: Option<PathBuf>, cfg: Option<MeshNodeConfig>) -> Self {
        // Resolve base_dir: explicit arg > cfg.base_dir > cwd
        let effective_base_dir = base_dir
            .clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

        let mut cfg = cfg.unwrap_or_else(|| Self::load_config(&effective_base_dir));

        // Store the resolved base_dir in cfg if not already set
        if cfg.base_dir.is_none() {
            cfg.base_dir = Some(effective_base_dir.clone());
        }

        let base_dir = cfg.base_dir.clone().unwrap_or(effective_base_dir);

        let keys = crate::auth::load_or_generate_keys_save(&base_dir);

        // Load authorized keys from file
        let mut authorized_keys_vec = match crate::auth::load_authorized_keys(&base_dir) {
            Ok(keys) => {
                info!("Loaded {} authorized keys from file", keys.len());
                keys
            }
            Err(e) => {
                error!("Failed to load authorized_keys: {}", e);
                Vec::new()
            }
        };

        // Append authorized keys from config if present
        if let Some(ref config_keys) = cfg.authorized_keys {
            let joined = config_keys.join("\n");
            match crate::auth::parse_authorized_keys_content(&joined) {
                Ok(entries) => {
                    info!("Added {} authorized keys from config", entries.len());
                    authorized_keys_vec.extend(entries);
                }
                Err(e) => error!("Failed to parse config authorized_keys: {}", e),
            }
        }

        // Load CA keys from file
        let mut ca_keys_vec = match crate::auth::load_authorized_cas(&base_dir) {
            Ok(cas) => {
                info!("Loaded {} CA keys from file", cas.len());
                cas
            }
            Err(e) => {
                error!("Failed to load authorized_cas: {}", e);
                Vec::new()
            }
        };

        // Append CA keys from config if present
        if let Some(ref config_cas) = cfg.ca_keys {
            for line in config_cas {
                match line.parse::<ssh_key::PublicKey>() {
                    Ok(key) => ca_keys_vec.push(key),
                    Err(e) => error!("Failed to parse config CA key: {} - {}", line, e),
                }
            }
            info!("Added {} CA keys from config", config_cas.len());
        }

        MeshNode {
            cfg,
            keys,
            clients: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            id_counter: Arc::new(std::sync::Mutex::new(0)),
            authorized_keys: Arc::new(authorized_keys_vec),
            ca_keys: Arc::new(ca_keys_vec),
            active_handlers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            connected_clients: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            server_handle: Arc::new(std::sync::Mutex::new(None)),
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

    /// Convenience accessor for base_dir from config.
    pub fn base_dir(&self) -> PathBuf {
        self.cfg
            .base_dir
            .clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
    }

    /// Convenience accessor for ssh_port from config.
    pub fn ssh_port(&self) -> u16 {
        self.cfg.ssh_port.unwrap_or(0)
    }

    /// Convenience accessor for http_port from config.
    pub fn http_port(&self) -> Option<u16> {
        self.cfg.http_port
    }

    /// Convenience accessor for sftp_server_path from config.
    pub fn sftp_server_path(&self) -> Option<&str> {
        self.cfg.sftp_server_path.as_deref()
    }

    /// Convenience accessor for sftp_root from config, defaulting to base_dir.
    pub fn sftp_root(&self) -> PathBuf {
        self.cfg
            .sftp_root
            .clone()
            .unwrap_or_else(|| self.base_dir())
    }
}

impl server::Server for MeshNode {
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
    server: MeshNode,
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
            {
                let mut active_handlers = server_clone.active_handlers.lock().unwrap();
                active_handlers.remove(&handler_id);
            }

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

/// Type alias for backward compatibility.
pub type SshServer = MeshNode;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    #[test]
    fn test_mesh_node_creation() {
        let temp_dir = tempfile::Builder::new()
            .prefix("ssh_server_test")
            .tempdir()
            .expect("Failed to create temp dir");
        let base_dir = temp_dir.path().to_path_buf();

        let server = MeshNode::new(Some(base_dir), None);
        let config = server.get_config();

        // Verify some configuration settings
        assert_eq!(config.keys.len(), 1);
        match &config.server_id {
            russh::SshId::Standard(id) => assert_eq!(id, "SSH-2.0-Rust-SSH-Server"),
            _ => panic!("Unexpected server ID format"),
        }
    }

    #[test]
    fn test_mesh_node_config_default() {
        let cfg = MeshNodeConfig::default();
        assert!(cfg.sftp_server_path.is_none());
        assert!(cfg.sftp_root.is_none());
        assert!(cfg.base_dir.is_none());
        assert!(cfg.ssh_port.is_none());
        assert!(cfg.http_port.is_none());
        assert!(cfg.authorized_keys.is_none());
        assert!(cfg.ca_keys.is_none());
    }

    #[test]
    fn test_mesh_node_config_json() {
        let temp_dir = tempfile::Builder::new()
            .prefix("mesh_cfg_test")
            .tempdir()
            .expect("Failed to create temp dir");
        let base_dir = temp_dir.path().to_path_buf();

        let json_content = r#"{"sftp_server_path": "/usr/lib/sftp-server"}"#;
        std::fs::write(base_dir.join("mesh.json"), json_content).unwrap();

        let cfg = MeshNode::load_config(&base_dir);
        assert_eq!(
            cfg.sftp_server_path,
            Some("/usr/lib/sftp-server".to_string())
        );
    }

    #[test]
    fn test_mesh_node_config_yaml() {
        let temp_dir = tempfile::Builder::new()
            .prefix("mesh_cfg_test")
            .tempdir()
            .expect("Failed to create temp dir");
        let base_dir = temp_dir.path().to_path_buf();

        let yaml_content = "sftp_server_path: /usr/lib/sftp-server\n";
        std::fs::write(base_dir.join("mesh.yaml"), yaml_content).unwrap();

        let cfg = MeshNode::load_config(&base_dir);
        assert_eq!(
            cfg.sftp_server_path,
            Some("/usr/lib/sftp-server".to_string())
        );
    }
}
