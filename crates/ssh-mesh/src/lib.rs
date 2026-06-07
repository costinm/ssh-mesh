#[cfg(feature = "test-utils")]
pub mod test_utils;

use anyhow::Context as AnyhowContext;
use log::{error, info};
use russh::keys::PrivateKey;
use russh::server;
use serde::{Deserialize, Serialize};
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
pub mod trusted_transport;
pub mod utils;

pub use sshd::SshHandler;

/// A local port forward configuration.
///
/// Listens on `bind_address:port` locally and forwards through the SSH
/// tunnel to `host:host_port` on the remote side.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct LocalForwardConfig {
    /// Local address to bind (default "127.0.0.1").
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    /// Local port to listen on.
    pub port: u16,
    /// Remote host to forward to.
    pub host: String,
    /// Remote port to forward to.
    pub host_port: u16,
}

/// A remote port forward configuration.
///
/// Asks the SSH server to listen on `bind_address:port` and forward
/// connections back through the tunnel to `host:host_port` locally.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RemoteForwardConfig {
    /// Remote address the server binds (default "127.0.0.1").
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    /// Remote port the server listens on.
    pub port: u16,
    /// Local host to connect to.
    pub host: String,
    /// Local port to connect to.
    pub host_port: u16,
}

fn default_bind_address() -> String {
    "127.0.0.1".to_string()
}

fn default_ssh_port() -> u16 {
    22
}

/// Configuration for an outgoing SSH client connection.
///
/// Modeled after `~/.ssh/config` Host entries, with local/remote
/// forward support and optional known host keys.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SshClientConfig {
    /// Transport to use for the outgoing connection: "tcp", "vsock", or "uds".
    #[serde(default = "default_client_transport", alias = "Transport")]
    pub transport: String,

    /// Hostname or IP to connect to.
    #[serde(alias = "Hostname", alias = "HostName")]
    pub hostname: Option<String>,

    /// SSH port (default 22).
    #[serde(default = "default_ssh_port", alias = "Port")]
    pub port: u16,

    /// Username for authentication.
    #[serde(default, alias = "User")]
    pub user: String,

    /// Virtio-vsock CID for trusted transport connections.
    #[serde(default, alias = "VsockCid")]
    pub vsock_cid: Option<u32>,

    /// Virtio-vsock port for trusted transport connections.
    #[serde(default, alias = "VsockPort")]
    pub vsock_port: Option<u32>,

    /// Unix domain socket path for trusted transport connections.
    #[serde(default, alias = "UdsPath")]
    pub uds_path: Option<PathBuf>,

    /// Expected host public keys (OpenSSH format).
    /// If empty, TOFU (Trust-On-First-Use) is used.
    /// If set, the server's key must match one of these.
    #[serde(default, alias = "HostKey")]
    pub keys: Vec<String>,

    /// Keep the connection alive and reconnect on failure.
    #[serde(default, alias = "KeepAlive")]
    pub keep_alive: bool,

    /// Reconnect interval in seconds when keep_alive is true.
    #[serde(default = "default_reconnect_interval")]
    pub reconnect_interval_secs: u64,

    /// Local port forwards (like `ssh -L`).
    #[serde(default, alias = "LocalForward")]
    pub local_forward: Vec<LocalForwardConfig>,

    /// Remote port forwards (like `ssh -R`).
    #[serde(default, alias = "RemoteForward")]
    pub remote_forward: Vec<RemoteForwardConfig>,
}

fn default_reconnect_interval() -> u64 {
    5
}

fn default_client_transport() -> String {
    "tcp".to_string()
}

/// SSH session routing rule.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SshRouteConfig {
    /// Logical route name, also used as the cached connection key.
    pub name: String,
    /// Exact incoming SSH username to match.
    #[serde(default)]
    pub user: Option<String>,
    /// Prefix match for incoming SSH username.
    #[serde(default)]
    pub user_prefix: Option<String>,
    /// Exact command to match.
    #[serde(default)]
    pub command: Option<String>,
    /// Prefix match for incoming command.
    #[serde(default)]
    pub command_prefix: Option<String>,
    /// Substring match for incoming command.
    #[serde(default)]
    pub command_contains: Option<String>,
    /// Exact incoming direct-tcpip host to match for jump-host routing.
    #[serde(default)]
    pub jump_host: Option<String>,
    /// Exact incoming direct-tcpip port to match for jump-host routing.
    #[serde(default)]
    pub jump_port: Option<u16>,
    /// Host to connect to from inside the routed target. Defaults to the incoming host.
    #[serde(default)]
    pub target_host: Option<String>,
    /// Port to connect to from inside the routed target. Defaults to the incoming port.
    #[serde(default)]
    pub target_port: Option<u16>,
    /// Optional mesh-init service to prepare before connecting.
    #[serde(default)]
    pub activation_service: Option<String>,
    /// Client connection to use after activation.
    pub client: SshClientConfig,
}

/// Configurable fields for MeshNode, loadable from JSON or YAML.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MeshNodeConfig {
    /// All configs are relative to this directory.
    pub base_dir: Option<PathBuf>,

    /// ssh-mesh application config directory.
    ///
    /// Per-user SSH authorization lives under `users/<USER>/authorized_keys`
    /// in this directory.
    pub config_dir: Option<PathBuf>,

    /// SSH server port.
    pub ssh_port: Option<u16>,

    /// HTTP server port (plain http)
    pub http_port: Option<u16>,

    /// Trusted SSH listener over virtio-vsock. This transport uses SSH as a mux
    /// with none-auth and no payload encryption.
    pub trusted_vsock_port: Option<u32>,

    /// CID to bind for the trusted virtio-vsock listener. Defaults to ANY.
    pub trusted_vsock_cid: Option<u32>,

    /// Trusted SSH listener over a Unix domain socket.
    pub trusted_uds_path: Option<PathBuf>,

    /// Path to the sftp server binary. Not using built-in to
    /// keep server isolated.
    pub sftp_server_path: Option<String>,

    /// Root directory for SFTP access.
    pub sftp_root: Option<PathBuf>,

    /// Optional list of authorized public keys (OpenSSH format lines).
    /// If present, these are used in addition to keys loaded from the
    /// `authorized_keys` file in base_dir.
    pub authorized_keys: Option<Vec<String>>,

    /// Optional list of CA public keys (OpenSSH format).
    /// If present, these are used in addition to CAs loaded from
    /// the `authorized_cas` file in base_dir.
    pub ca_keys: Option<Vec<String>>,

    /// Map of named SSH client connections to establish at startup.
    /// Keys are logical names; values are `SshClientConfig` entries.
    #[serde(default)]
    pub clients: HashMap<String, SshClientConfig>,

    /// Incoming SSH exec/shell routing rules.
    #[serde(default)]
    pub ssh_routes: Vec<SshRouteConfig>,
}

pub trait MeshListener: Send + Sync {
    fn on_ssh_connection(&self, client_id: u64, user: &str);
    fn on_stream(&self, client_id: u64, host: &str, port: u16, stream: tokio::io::DuplexStream);
}

// MeshNode is the main server struct (formerly SshServer).
#[derive(Clone)]
pub struct MeshNode {
    pub cfg: MeshNodeConfig,
    pub keys: PrivateKey,
    pub clients: Arc<tokio::sync::Mutex<Vec<SshClientConfig>>>,
    pub id_counter: Arc<std::sync::Mutex<u64>>,
    pub authorized_keys: Arc<Vec<auth::AuthorizedKeyEntry>>,
    pub ca_keys: Arc<Vec<ssh_key::PublicKey>>,
    pub active_handlers:
        Arc<std::sync::Mutex<HashMap<u64, Arc<tokio::sync::Mutex<sshd::SshHandler>>>>>,
    pub connected_clients: Arc<tokio::sync::Mutex<HashMap<u64, ConnectedClientInfo>>>,
    pub route_client_manager: Arc<sshc::SshClientManager>,
    pub route_connections: Arc<tokio::sync::Mutex<HashMap<String, u64>>>,
    pub server_handle:
        Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<Result<(), anyhow::Error>>>>>,
    pub listeners: Arc<tokio::sync::Mutex<Vec<Arc<dyn MeshListener>>>>,
}

/// Information about a connected client
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ConnectedClientInfo {
    pub id: u64,
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

        let route_client_manager = Arc::new(sshc::SshClientManager::new(
            keys.clone(),
            ca_keys_vec.clone(),
            None,
            None,
        ));

        MeshNode {
            cfg,
            keys,
            clients: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            id_counter: Arc::new(std::sync::Mutex::new(0)),
            authorized_keys: Arc::new(authorized_keys_vec),
            ca_keys: Arc::new(ca_keys_vec),
            active_handlers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            connected_clients: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            route_client_manager,
            route_connections: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            server_handle: Arc::new(std::sync::Mutex::new(None)),
            listeners: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    pub fn add_listener(&self, listener: Arc<dyn MeshListener>) {
        let mut listeners = self.listeners.blocking_lock();
        listeners.push(listener);
    }

    pub fn get_config(&self) -> server::Config {
        let mut config = server::Config::default();
        config.keys.push(self.keys.clone());
        config.max_auth_attempts = 3;
        config.server_id =
            russh::SshId::Standard(std::borrow::Cow::Borrowed("SSH-2.0-Rust-SSH-Server"));
        config
    }

    pub fn get_trusted_transport_config(&self) -> server::Config {
        let mut config = self.get_config();
        config.methods = (&[russh::MethodKind::None][..]).into();
        config.auth_rejection_time = std::time::Duration::ZERO;
        config.auth_rejection_time_initial = Some(std::time::Duration::ZERO);
        config.limits = russh::Limits::new(
            1 << 30,
            1 << 30,
            std::time::Duration::from_secs(365 * 24 * 60 * 60),
        );
        config.preferred = trusted_transport::trusted_preferred();
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

    /// Convenience accessor for ssh-mesh config directory.
    pub fn config_dir(&self) -> PathBuf {
        self.cfg
            .config_dir
            .clone()
            .or_else(|| std::env::var("SSH_MESH_CONFIG").ok().map(PathBuf::from))
            .unwrap_or_else(|| {
                let mut path = std::env::var("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("/tmp"));
                path.push(".config");
                path.push("ssh-mesh");
                path
            })
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
        self.new_client_for_transport(false)
    }
}

impl MeshNode {
    fn new_client_for_transport(&mut self, trusted_transport: bool) -> SshHandler {
        let mut id = self.id_counter.lock().unwrap();
        *id += 1;
        let mut handler = SshHandler::new(*id, self.clone());
        handler.set_trusted_transport(trusted_transport);

        // Store the handler in active_handlers
        let handler_arc = Arc::new(tokio::sync::Mutex::new(handler.clone()));
        let mut active_handlers = self.active_handlers.lock().unwrap();
        active_handlers.insert(*id, handler_arc);

        // Notify listeners about the new connection
        let listeners = self.listeners.clone();
        let id_val = *id;
        tokio::spawn(async move {
            let listeners = listeners.lock().await;
            for l in listeners.iter() {
                l.on_ssh_connection(id_val, ""); // User is not yet known
            }
        });

        handler
    }
}

pub async fn run_ssh_stream<S>(
    config: Arc<server::Config>,
    stream: S,
    mut server: MeshNode,
    peer_addr: Option<SocketAddr>,
    label: &'static str,
    trusted_transport: bool,
) -> Result<(), anyhow::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let _ = peer_addr;
    let handler = server.new_client_for_transport(trusted_transport);
    let handler_id = handler.id;

    debug!("Starting {} SSH session for handler {}", label, handler_id);

    match russh::server::run_stream(config, stream, handler).await {
        Ok(session) => {
            info!(
                "{} SSH session stream started for handler {}",
                label, handler_id
            );
            if let Err(e) = session.await {
                error!(
                    "{} SSH session error for handler {}: {:?}",
                    label, handler_id, e
                );
            }
            info!(
                "{} SSH session future finished for handler {}",
                label, handler_id
            );
        }
        Err(e) => {
            error!(
                "{} SSH handshake failed for handler {}: {}",
                label, handler_id, e
            );
        }
    }

    {
        let mut active_handlers = server.active_handlers.lock().unwrap();
        active_handlers.remove(&handler_id);
    }

    let mut clients = server.connected_clients.lock().await;
    if clients.remove(&handler_id).is_some() {
        debug!("Removed client {} from connected_clients", handler_id);
    }

    Ok(())
}

// Function to start the SSH server
#[instrument(skip(config, server), fields(port = port))]
pub async fn run_ssh_server(
    port: u16,
    config: server::Config,
    server: MeshNode,
) -> Result<(), anyhow::Error> {
    let config = Arc::new(config);

    // Check for socket activation via LISTEN_FD
    let listener = if let Ok(fd_str) = std::env::var("LISTEN_FD") {
        if let Ok(fd) = fd_str.parse::<i32>() {
            info!("Using activated listener FD {} for SSH server", fd);
            use std::os::fd::FromRawFd;
            let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
            std_listener.set_nonblocking(true)?;
            tokio::net::TcpListener::from_std(std_listener)?
        } else {
            let addr = format!("0.0.0.0:{}", port);
            info!("Starting SSH server on {}", addr);
            tokio::net::TcpListener::bind(&addr).await?
        }
    } else {
        let addr = format!("0.0.0.0:{}", port);
        info!("Starting SSH server on {}", addr);
        tokio::net::TcpListener::bind(&addr).await?
    };

    loop {
        debug!("Waiting for new connection...");
        let (stream, peer_addr) = listener.accept().await?;
        info!("Accepted connection from {:?}", peer_addr);
        let config = config.clone();
        let server_clone = server.clone();

        tokio::spawn(async move {
            if let Err(e) =
                run_ssh_stream(config, stream, server_clone, Some(peer_addr), "tcp", false).await
            {
                error!("TCP SSH stream failed: {}", e);
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
        assert!(cfg.clients.is_empty());
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

    #[test]
    fn test_mesh_node_config_clients_yaml() {
        let temp_dir = tempfile::Builder::new()
            .prefix("mesh_cfg_test")
            .tempdir()
            .expect("Failed to create temp dir");
        let base_dir = temp_dir.path().to_path_buf();

        let yaml_content = r#"
clients:
  gateway:
    hostname: gw.example.com
    port: 2222
    user: deploy
    keep_alive: true
    reconnect_interval_secs: 10
    keys:
      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTestingOnly"
    local_forward:
      - bind_address: "127.0.0.1"
        port: 8080
        host: "10.0.0.1"
        host_port: 80
    remote_forward:
      - port: 9090
        host: "127.0.0.1"
        host_port: 3000
  backup:
    hostname: backup.local
    user: root
"#;
        std::fs::write(base_dir.join("mesh.yaml"), yaml_content).unwrap();

        let cfg = MeshNode::load_config(&base_dir);
        assert_eq!(cfg.clients.len(), 2);

        let gw = cfg.clients.get("gateway").expect("gateway client");
        assert_eq!(gw.hostname.as_deref(), Some("gw.example.com"));
        assert_eq!(gw.port, 2222);
        assert_eq!(gw.user, "deploy");
        assert!(gw.keep_alive);
        assert_eq!(gw.reconnect_interval_secs, 10);
        assert_eq!(gw.keys.len(), 1);
        assert_eq!(gw.local_forward.len(), 1);
        assert_eq!(gw.local_forward[0].port, 8080);
        assert_eq!(gw.local_forward[0].host, "10.0.0.1");
        assert_eq!(gw.local_forward[0].host_port, 80);
        assert_eq!(gw.remote_forward.len(), 1);
        assert_eq!(gw.remote_forward[0].port, 9090);
        assert_eq!(gw.remote_forward[0].host_port, 3000);

        let backup = cfg.clients.get("backup").expect("backup client");
        assert_eq!(backup.hostname.as_deref(), Some("backup.local"));
        assert_eq!(backup.port, 22); // default
        assert_eq!(backup.user, "root");
        assert!(!backup.keep_alive); // default
        assert!(backup.keys.is_empty()); // default - use TOFU
        assert!(backup.local_forward.is_empty());
        assert!(backup.remote_forward.is_empty());
    }
}
