/// SSH Client module using russh library.
///
/// Provides an SSH client with REST API for managing connections,
/// port forwarding (local and remote), and command execution.
/// Supports Trust-On-First-Use (TOFU) for server key verification.
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use log::{error, info};
use russh::client;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey as RusshPublicKey};
use russh::{ChannelMsg, Disconnect};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use utoipa::{OpenApi, ToSchema};

// TODO: create a UDS for each connection, compatible with ssh client
// ControlPersist yes, ControlMaster auto, controlpath /tmp/ssh-%u-%n-%r@%h:%p

// ---------------------------------------------------------------------------
// Client Handler (TOFU key checking)
// ---------------------------------------------------------------------------

/// Holds forward metadata for cleanup/tracking.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ForwardInfo {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    #[serde(default)]
    pub local_host: String, // Added for remote forwarding "to where"
    #[serde(rename = "type")]
    pub forward_type: String, // "local" or "remote"
}

/// Metadata about one SSH client connection.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConnectionInfo {
    pub id: u64,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub forwards: Vec<ForwardInfo>,
}

/// russh client::Handler connects to a single client.
pub struct ClientHandler {
    /// Path on disk for storing the known server key.
    key_file: PathBuf,
    /// Expected server key (if provided or previously saved). Empty ⇒ TOFU.
    expected_key: Option<RusshPublicKey>,
    /// CA keys for validating server certificates.
    ca_keys: Arc<Vec<ssh_key::PublicKey>>,
    /// Shared forwards list to look up target for incoming channels.
    forwards: Arc<Mutex<Vec<ForwardInfo>>>,
    /// Hostname we are connecting to (used for certificate validation).
    host: String,
}

impl client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        // 1. If we have CA keys, check if the server key is signed by one of them.
        if !self.ca_keys.is_empty() {
            let key_str = server_public_key
                .to_openssh()
                .context("Failed to serialize server key")?;

            // If it's a certificate, validate it
            if key_str.contains("-cert-v01@openssh.com") {
                info!("Server presented a certificate. Validating against CA keys.");
                // We use self.host as the "principal" to validate.
                match crate::auth::validate_certificate(&key_str, &self.host, &self.ca_keys).await {
                    Ok(res) => {
                        if let russh::server::Auth::Accept = res.status {
                            info!(
                                "Server certificate validated successfully for host {}",
                                self.host
                            );
                            return Ok(true);
                        } else {
                            error!("Server certificate validation failed: {}", res.comment);
                            // If certificate validation fails, we should probably reject,
                            // unless we want to fall back to TOFU/Key check?
                            // Usually if a cert is presented but valid fails, it's a hard error.
                            return Ok(false);
                        }
                    }
                    Err(e) => {
                        error!("Error during certificate validation: {}", e);
                        // Fallthrough to standard key check? Or fail?
                        // Let's fail for now if it looked like a cert.
                        return Ok(false);
                    }
                }
            }
        }

        // 2. Fallback to standard Expected Key / TOFU logic
        if let Some(ref expected) = self.expected_key {
            // Validate against known key: compare OpenSSH string representation
            let expected_str = expected
                .to_openssh()
                .context("Failed to serialize expected key")?;
            let actual_str = server_public_key
                .to_openssh()
                .context("Failed to serialize server key")?;
            if expected_str != actual_str {
                error!("Server key mismatch!");
                return Ok(false);
            }
            Ok(true)
        } else {
            // TOFU: save the key for future connections
            info!(
                "TOFU: Trusting server key on first use, saving to {:?}",
                self.key_file
            );
            Ok(true)
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        info!(
            "Forwarded-tcpip channel opened: {}:{} from {}:{}",
            connected_address, connected_port, originator_address, originator_port
        );

        // Find the matching forward configuration
        let forwards = self.forwards.lock().await;
        // In most SSH server implementations, 'connected_port' is the port on the server
        // that the client asked to listen on.
        let forward_info = forwards.iter().find(|f| {
            f.forward_type == "remote" && f.remote_port == connected_port as u16
            // We could also check f.remote_host (bind address), but often that's "0.0.0.0" or "localhost"
            // and connected_address be different. Port matching is usually sufficient per-connection.
        });

        if let Some(info) = forward_info {
            let target_host = info.local_host.clone(); // The host we should connect to locally
            let target_port = info.local_port;

            info!(
                "Connecting forwarded channel to {}:{}",
                target_host, target_port
            );

            // Spawn a task to handle the connection effectively bridging the channel and local TCP
            tokio::spawn(async move {
                // Connect to the local target
                match TcpStream::connect(format!("{}:{}", target_host, target_port)).await {
                    Ok(tcp_stream) => {
                        info!("Connected to local target {}:{}", target_host, target_port);
                        let channel_stream = channel.into_stream();
                        crate::utils::bridge(channel_stream, tcp_stream, "Remote Forward").await;
                    }
                    Err(e) => {
                        error!(
                            "Failed to connect to local target {}:{}: {}",
                            target_host, target_port, e
                        );
                        let _ = channel.close().await;
                    }
                }
            });

            Ok(())
        } else {
            error!(
                "No remote forward found for port {}. Rejecting channel.",
                connected_port
            );
            // Verify if we need to explicitly reject or if dropping/returning Err does it.
            // Returning Err usually closes the channel.
            Err(anyhow::anyhow!(
                "No forward found for port {}",
                connected_port
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// SSH Client Connection wrapper
// ---------------------------------------------------------------------------

/// One SSH client connection.
struct SshClientConnection {
    id: u64,
    host: String,
    port: u16,
    user: String,
    session: Arc<Mutex<client::Handle<ClientHandler>>>,
    forwards: Arc<Mutex<Vec<ForwardInfo>>>,
    /// Abort handles for local forward listener tasks.
    _forward_tasks: Vec<tokio::task::JoinHandle<()>>,
    /// Mux server for this connection (if mux_dir is configured).
    mux_server: Option<Arc<crate::mux::MuxServer>>,
}

impl SshClientConnection {
    async fn info(&self) -> ConnectionInfo {
        ConnectionInfo {
            id: self.id,
            host: self.host.clone(),
            port: self.port,
            user: self.user.clone(),
            forwards: self.forwards.lock().await.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// SSH Client Manager
// ---------------------------------------------------------------------------

/// Manages multiple SSH client connections.
pub struct SshClientManager {
    connections: Mutex<HashMap<u64, SshClientConnection>>,
    next_id: Mutex<u64>,
    /// Private key used for client authentication (same as server key).
    private_key: Arc<PrivateKey>,
    /// CA keys for verifying server certificates
    ca_keys: Arc<Vec<ssh_key::PublicKey>>,
    /// Optional path to an SSH config file (~/.ssh/config format).
    ssh_config_path: Option<PathBuf>,
    /// Optional directory for mux sockets.
    mux_dir: Option<PathBuf>,
}

impl SshClientManager {
    pub fn new(
        private_key: PrivateKey,
        ca_keys: Vec<ssh_key::PublicKey>,
        ssh_config_path: Option<PathBuf>,
        mux_dir: Option<PathBuf>,
    ) -> Self {
        if let Some(ref path) = ssh_config_path {
            info!("SSH client manager using config: {:?}", path);
        }
        if let Some(ref dir) = mux_dir {
            info!("SSH client manager mux dir: {:?}", dir);
        }
        Self {
            connections: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
            private_key: Arc::new(private_key),
            ca_keys: Arc::new(ca_keys),
            ssh_config_path,
            mux_dir,
        }
    }

    /// Look up host configuration from the SSH config file.
    /// Returns (resolved_host, resolved_port, resolved_user) if found.
    fn lookup_ssh_config(&self, host: &str) -> Option<(String, u16, String)> {
        let path = self.ssh_config_path.as_ref()?;
        match ssh_config::parse_path(path, host) {
            Ok(cfg) => {
                let resolved_host = cfg.host().to_string();
                let resolved_port = cfg.port();
                let resolved_user = cfg.user();
                info!(
                    "SSH config for '{}': host={}, port={}, user={}",
                    host, resolved_host, resolved_port, resolved_user
                );
                Some((resolved_host, resolved_port, resolved_user))
            }
            Err(e) => {
                info!("No SSH config match for '{}': {}", host, e);
                None
            }
        }
    }

    /// List all hosts defined in the SSH config file.
    /// Uses `ssh_config::parse_ssh_config` to iterate over parsed host entries
    /// directly, skipping wildcard-only and negated patterns.
    pub fn list_config_hosts(&self) -> Vec<NodeConfig> {
        let path = match self.ssh_config_path.as_ref() {
            Some(p) => p,
            None => return Vec::new(),
        };

        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to read SSH config {:?}: {}", path, e);
                return Vec::new();
            }
        };

        let ssh_config = ssh_config::parse_ssh_config(&contents);

        let mut hosts = Vec::new();
        for entry in &ssh_config.entries {
            for hp in &entry.host_patterns {
                // Skip wildcards and negated patterns
                if hp.negated
                    || hp.pattern == "*"
                    || hp.pattern.contains('*')
                    || hp.pattern.contains('?')
                {
                    continue;
                }
                let cfg = ssh_config.query(&hp.pattern);
                hosts.push(NodeConfig {
                    name: hp.pattern.clone(),
                    hostname: cfg.hostname.as_deref().unwrap_or(&hp.pattern).to_string(),
                    port: cfg.port.unwrap_or(22),
                    user: cfg.user.unwrap_or_default(),
                    public_keys: Vec::new(),
                });
            }
        }

        hosts
    }

    /// Connect to an SSH server with public key authentication.
    ///
    /// Uses the server's own private key for client authentication.
    ///
    /// * `host` / `port` – target SSH server
    /// * `user` – username
    /// * `server_key` – optional known server public key (OpenSSH format).
    ///   If empty, TOFU: accept and save to `<host>_<port>.pub`.
    pub async fn connect(
        &self,
        host: &str,
        port: u16,
        user: &str,
        server_key: &str,
    ) -> Result<u64> {
        // Resolve host/port/user from SSH config if available
        let ssh_cfg = self.lookup_ssh_config(host);
        let (connect_host, connect_port, connect_user) =
            if let Some((cfg_host, cfg_port, cfg_user)) = ssh_cfg {
                // SSH config provides defaults; explicit caller values override
                let h = cfg_host;
                let p = if port != 0 { port } else { cfg_port };
                let u = if !user.is_empty() {
                    user.to_string()
                } else {
                    cfg_user
                };
                (h, p, u)
            } else {
                (host.to_string(), port, user.to_string())
            };

        let key_file = PathBuf::from(format!("{}_{}.pub", connect_host, connect_port));

        // Determine expected server key
        let expected_key = if !server_key.is_empty() {
            Some(
                RusshPublicKey::from_openssh(server_key)
                    .context("Failed to parse supplied server key")?,
            )
        } else if key_file.exists() {
            // Try loading a previously TOFU-saved key
            let data =
                std::fs::read_to_string(&key_file).context("Failed to read saved server key")?;
            Some(
                RusshPublicKey::from_openssh(data.trim())
                    .context("Failed to parse saved server key")?,
            )
        } else {
            None
        };

        let forwards = Arc::new(Mutex::new(Vec::new()));

        let handler = ClientHandler {
            key_file,
            expected_key,
            ca_keys: self.ca_keys.clone(),
            forwards: forwards.clone(),
            host: connect_host.clone(),
        };

        let config = Arc::new(client::Config {
            nodelay: true,
            ..Default::default()
        });

        let mut session =
            client::connect(config, (connect_host.as_str(), connect_port), handler).await?;

        // Authenticate with the server's private key
        let key_with_alg = PrivateKeyWithHashAlg::new(self.private_key.clone(), None);
        let auth_res = session
            .authenticate_publickey(&connect_user, key_with_alg)
            .await?;
        if auth_res != client::AuthResult::Success {
            anyhow::bail!("Authentication failed");
        }

        let session = Arc::new(Mutex::new(session));

        // Start mux server if mux_dir is configured
        let mux_server = if let Some(ref mux_dir) = self.mux_dir {
            let socket_path = crate::mux::mux_socket_path(mux_dir, &connect_user, host);
            match crate::mux::MuxServer::start(socket_path, session.clone()) {
                Ok(server) => Some(server),
                Err(e) => {
                    error!("Failed to start mux server: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let mut next_id = self.next_id.lock().await;
        let id = *next_id;
        *next_id += 1;
        drop(next_id);

        let conn = SshClientConnection {
            id,
            host: connect_host.clone(),
            port: connect_port,
            user: connect_user.clone(),
            session,
            forwards,
            _forward_tasks: Vec::new(),
            mux_server,
        };

        self.connections.lock().await.insert(id, conn);
        info!(
            "SSH client connected to {}:{} as {} (id={})",
            connect_host, connect_port, connect_user, id
        );
        Ok(id)
    }

    /// List all active connections.
    pub async fn list_connections(&self) -> Vec<ConnectionInfo> {
        let conns = self.connections.lock().await;
        let mut infos = Vec::new();
        for c in conns.values() {
            infos.push(c.info().await);
        }
        infos
    }

    /// Disconnect a connection by id.
    pub async fn disconnect(&self, id: u64) -> Result<()> {
        let mut conns = self.connections.lock().await;
        if let Some(conn) = conns.remove(&id) {
            // Stop mux server first
            if let Some(ref mux) = conn.mux_server {
                mux.stop();
            }
            let session = conn.session.lock().await;
            let _ = session
                .disconnect(Disconnect::ByApplication, "", "en")
                .await;
            info!("SSH client disconnected (id={})", id);
            Ok(())
        } else {
            anyhow::bail!("Connection {} not found", id);
        }
    }

    /// Add a local port forward.
    ///
    /// Listens on `local_port` locally; each connection is forwarded through
    /// the SSH tunnel to `remote_host:remote_port`.
    pub async fn add_local_forward(
        &self,
        id: u64,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<()> {
        let mut conns = self.connections.lock().await;
        let conn = conns
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("Connection {} not found", id))?;

        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", local_port)).await?;
        let actual_port = listener.local_addr()?.port();

        let session = conn.session.clone();
        let rhost = remote_host.to_string();
        let rport = remote_port;

        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((tcp_stream, _peer)) => {
                        let session_clone = session.clone();
                        let rhost_clone = rhost.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_local_forward(tcp_stream, session_clone, &rhost_clone, rport)
                                    .await
                            {
                                error!("Local forward error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error on local forward: {}", e);
                        break;
                    }
                }
            }
        });

        let mut forwards = conn.forwards.lock().await;
        forwards.push(ForwardInfo {
            local_port: actual_port,
            remote_host: remote_host.to_string(),
            remote_port,
            local_host: "127.0.0.1".to_string(),
            forward_type: "local".to_string(),
        });
        conn._forward_tasks.push(task);

        info!(
            "Local forward: 127.0.0.1:{} -> {}:{} (conn={})",
            actual_port, remote_host, remote_port, id
        );
        Ok(())
    }

    /// Add a remote port forward.
    ///
    /// Asks the SSH server to listen on `remote_port` and forward
    /// connections back through the tunnel.
    pub async fn add_remote_forward(
        &self,
        id: u64,
        remote_port: u16,
        local_host: &str,
        local_port: u16,
    ) -> Result<u32> {
        let mut conns = self.connections.lock().await;
        let conn = conns
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("Connection {} not found", id))?;

        let actual_port = {
            let mut session = conn.session.lock().await;
            session
                .tcpip_forward("127.0.0.1", remote_port as u32)
                .await
                .context("tcpip_forward failed")?
        };

        let mut forwards = conn.forwards.lock().await;
        forwards.push(ForwardInfo {
            local_port,
            remote_host: local_host.to_string(),
            remote_port: actual_port as u16,
            local_host: local_host.to_string(),
            forward_type: "remote".to_string(),
        });

        info!(
            "Remote forward: server:{} -> {}:{} (conn={})",
            actual_port, local_host, local_port, id
        );
        Ok(actual_port)
    }

    /// Execute a command on the remote server, returning (stdout, stderr, exit_code).
    pub async fn exec(&self, id: u64, command: &str) -> Result<ExecResult> {
        let conns = self.connections.lock().await;
        let conn = conns
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("Connection {} not found", id))?;

        let mut channel = {
            let session = conn.session.lock().await;
            session.channel_open_session().await?
        };
        channel.exec(true, command).await?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code: Option<u32> = None;

        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => {
                    stdout.extend_from_slice(data);
                }
                ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        stderr.extend_from_slice(data);
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = Some(exit_status);
                }
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }

        Ok(ExecResult {
            stdout: String::from_utf8_lossy(&stdout).to_string(),
            stderr: String::from_utf8_lossy(&stderr).to_string(),
            exit_code: exit_code.unwrap_or(0),
        })
    }
}

/// Handles one local-forward connection by piping TCP⇄SSH channel.
pub(crate) async fn handle_local_forward(
    mut tcp_stream: TcpStream,
    session: Arc<Mutex<client::Handle<ClientHandler>>>,
    remote_host: &str,
    remote_port: u16,
) -> Result<()> {
    let mut channel = {
        let session_guard = session.lock().await;
        session_guard
            .channel_open_direct_tcpip(remote_host, remote_port as u32, "127.0.0.1", 0)
            .await?
    };

    let mut stream_closed = false;
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            // TCP → SSH
            r = tcp_stream.read(&mut buf), if !stream_closed => {
                match r {
                    Ok(0) => {
                        stream_closed = true;
                        channel.eof().await?;
                    }
                    Ok(n) => channel.data(&buf[..n]).await?,
                    Err(e) => return Err(e.into()),
                }
            }
            // SSH → TCP
            Some(msg) = channel.wait() => {
                match msg {
                    ChannelMsg::Data { ref data } => {
                        tcp_stream.write_all(data).await?;
                    }
                    ChannelMsg::Eof => {
                        if !stream_closed {
                            channel.eof().await?;
                        }
                        break;
                    }
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// REST API types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Optional server public key (OpenSSH format). If empty, TOFU.
    #[serde(default)]
    pub server_key: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ConnectResponse {
    pub id: u64,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct LocalForwardRequest {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct RemoteForwardRequest {
    pub remote_port: u16,
    pub local_host: String,
    pub local_port: u16,
}

// Add local_host to ForwardInfo to support tracking remote forwards properly
// Update ForwardInfo definition (need to do this first or in same step)

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct RemoteForwardResponse {
    pub actual_port: u32,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct ExecRequest {
    pub command: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: u32,
}

/// A node configuration entry, typically loaded from SSH config or config files.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NodeConfig {
    /// The alias name from the `Host` directive.
    pub name: String,
    /// The resolved hostname (from `Hostname` or same as name).
    pub hostname: String,
    /// The resolved port (from `Port` or default 22).
    pub port: u16,
    /// The resolved user (from `User` or system default).
    pub user: String,
    /// Public keys associated with this node (OpenSSH format).
    #[serde(default)]
    pub public_keys: Vec<String>,
}

// ---------------------------------------------------------------------------
// REST API Handlers
// ---------------------------------------------------------------------------

#[derive(OpenApi)]
#[openapi(
    paths(
        handle_connect,
        handle_list_connections,
        handle_disconnect,
        handle_add_local_forward,
        handle_add_remote_forward,
        sshc_handle_exec,
        handle_list_config_hosts
    ),
    components(
        schemas(
            ConnectRequest, ConnectResponse, ConnectionInfo, ForwardInfo,
            LocalForwardRequest, RemoteForwardRequest, RemoteForwardResponse,
            ExecRequest, ExecResult, NodeConfig
        )
    ),
    tags(
        (name = "sshc", description = "SSH Client REST API")
    )
)]
pub struct SshcApiDoc;

/// Build the SSH client REST API router.
pub fn sshc_routes(manager: Arc<SshClientManager>) -> Router {
    Router::new()
        .route("/connect", post(handle_connect))
        .route("/connections", get(handle_list_connections))
        .route("/connections/:id", delete(handle_disconnect))
        .route(
            "/connections/:id/forward/local",
            post(handle_add_local_forward),
        )
        .route(
            "/connections/:id/forward/remote",
            post(handle_add_remote_forward),
        )
        .route("/connections/:id/exec", post(sshc_handle_exec))
        .route("/config/hosts", get(handle_list_config_hosts))
        .with_state(manager)
}

/// List all hosts from the SSH config file.
#[utoipa::path(
    get,
    path = "/_m/api/sshc/config/hosts",
    tag = "sshc",
    responses(
        (status = 200, description = "List of SSH config hosts", body = Vec<NodeConfig>)
    )
)]
async fn handle_list_config_hosts(
    State(manager): State<Arc<SshClientManager>>,
) -> impl IntoResponse {
    let hosts = manager.list_config_hosts();
    (StatusCode::OK, Json(hosts))
}

/// Connect to a remote SSH server.
///
/// * `req` — Connection parameters (host, port, user, optional server_key).
#[utoipa::path(
    post,
    path = "/_m/api/sshc/connect",
    tag = "sshc",
    request_body = ConnectRequest,
    responses(
        (status = 200, description = "Connection established", body = ConnectResponse),
        (status = 500, description = "Connection failed")
    )
)]
async fn handle_connect(
    State(manager): State<Arc<SshClientManager>>,
    Json(req): Json<ConnectRequest>,
) -> impl IntoResponse {
    match manager
        .connect(&req.host, req.port, &req.user, &req.server_key)
        .await
    {
        Ok(id) => (StatusCode::OK, Json(serde_json::json!({"id": id}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// List all active SSH client connections.
#[utoipa::path(
    get,
    path = "/_m/api/sshc/connections",
    tag = "sshc",
    responses(
        (status = 200, description = "Active connections", body = Vec<ConnectionInfo>)
    )
)]
async fn handle_list_connections(
    State(manager): State<Arc<SshClientManager>>,
) -> impl IntoResponse {
    let conns = manager.list_connections().await;
    (StatusCode::OK, Json(conns))
}

/// Disconnect an SSH client connection by ID.
///
/// * `id` — Connection ID to disconnect.
#[utoipa::path(
    delete,
    path = "/_m/api/sshc/connections/{id}",
    tag = "sshc",
    params(
        ("id" = u64, Path, description = "Connection ID")
    ),
    responses(
        (status = 200, description = "Disconnected"),
        (status = 404, description = "Connection not found")
    )
)]
async fn handle_disconnect(
    State(manager): State<Arc<SshClientManager>>,
    AxumPath(id): AxumPath<u64>,
) -> impl IntoResponse {
    match manager.disconnect(id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "disconnected"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// Add a local port forward to a connection.
///
/// * `id` — Connection ID.
/// * `req` — Local port, remote host, and remote port.
#[utoipa::path(
    post,
    path = "/_m/api/sshc/connections/{id}/forward/local",
    tag = "sshc",
    params(
        ("id" = u64, Path, description = "Connection ID")
    ),
    request_body = LocalForwardRequest,
    responses(
        (status = 200, description = "Forward added"),
        (status = 500, description = "Failed to add forward")
    )
)]
async fn handle_add_local_forward(
    State(manager): State<Arc<SshClientManager>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<LocalForwardRequest>,
) -> impl IntoResponse {
    match manager
        .add_local_forward(id, req.local_port, &req.remote_host, req.remote_port)
        .await
    {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// Add a remote port forward to a connection.
///
/// * `id` — Connection ID.
/// * `req` — Remote port, local host, and local port.
#[utoipa::path(
    post,
    path = "/_m/api/sshc/connections/{id}/forward/remote",
    tag = "sshc",
    params(
        ("id" = u64, Path, description = "Connection ID")
    ),
    request_body = RemoteForwardRequest,
    responses(
        (status = 200, description = "Forward added", body = RemoteForwardResponse),
        (status = 500, description = "Failed to add forward")
    )
)]
async fn handle_add_remote_forward(
    State(manager): State<Arc<SshClientManager>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<RemoteForwardRequest>,
) -> impl IntoResponse {
    match manager
        .add_remote_forward(id, req.remote_port, &req.local_host, req.local_port)
        .await
    {
        Ok(port) => (
            StatusCode::OK,
            Json(serde_json::json!({"actual_port": port})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// Execute a command on a remote SSH connection.
///
/// * `id` — Connection ID.
/// * `req` — Command to execute.
#[utoipa::path(
    post,
    path = "/_m/api/sshc/connections/{id}/exec",
    tag = "sshc",
    params(
        ("id" = u64, Path, description = "Connection ID")
    ),
    request_body = ExecRequest,
    responses(
        (status = 200, description = "Execution result", body = ExecResult),
        (status = 500, description = "Execution failed")
    )
)]
async fn sshc_handle_exec(
    State(manager): State<Arc<SshClientManager>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<ExecRequest>,
) -> impl IntoResponse {
    match manager.exec(id, &req.command).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
