#[cfg(feature = "test-utils")]
pub mod test_utils;

use anyhow::Context as AnyhowContext;
use axum::{body::Body, extract::State, response::IntoResponse};
use bytes::Buf;
use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper::{Request, Response};
use log::{error, info};
use nix::libc::{ioctl, TIOCSCTTY};
use nix::unistd::{dup2, setsid};
use openpty::openpty;
use russh::keys::{PrivateKey, PublicKey, PublicKeyBase64};
use russh::server::Server;
use russh::{server, ChannelId, MethodKind};
use serde::Serialize;
use ssh_key::LineEnding;
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
#[allow(dead_code, unused)]
use std::{
    convert::Infallible,
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    sync::Arc,
    task::{Context, Poll},
    time::SystemTime,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::StreamExt;
use tracing::{debug, error as tracing_error, instrument, trace};

// use pmond::ProcMon;
use ws::WSServer;

// File paths for SSH authentication
const AUTHORIZED_KEYS_PATH: &str = ".ssh/authorized_keys";
const AUTHORIZED_CAS_PATH: &str = ".ssh/authorized_cas";
const DEBUG_PTY: bool = false;

pub mod handlers;

// Configuration for the SSH server
#[derive(Clone)]
#[allow(unused)]
pub struct SshServer {
    keys: PrivateKey,
    clients: Arc<tokio::sync::Mutex<Vec<usize>>>,
    id_counter: Arc<std::sync::Mutex<usize>>,
    pub authorized_keys: Arc<Vec<ssh_key::PublicKey>>,
    pub ca_keys: Arc<Vec<ssh_key::PublicKey>>,
    pub base_dir: PathBuf,
    /// Active SSH handlers indexed by their ID
    active_handlers: Arc<std::sync::Mutex<HashMap<usize, Arc<tokio::sync::Mutex<SshHandler>>>>>,
    /// Track connected clients with their remote forward listeners
    pub connected_clients: Arc<tokio::sync::Mutex<HashMap<usize, ConnectedClientInfo>>>,
}

/// Information about a connected client
#[derive(Clone, Debug, Serialize)]
pub struct ConnectedClientInfo {
    pub id: usize,
    pub user: String,
    pub remote_forward_listeners: Vec<(String, u32)>,
    pub connected_at: SystemTime,
}

#[derive(Clone)]
pub struct AppState {
    pub ssh_server: Arc<SshServer>,
    //pub proc_mon: Arc<ProcMon>,
    pub ws_server: Arc<WSServer>,
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
    pub fn new(id: usize, key: Option<PrivateKey>, base_dir: PathBuf) -> Self {
        let keys = match key {
            Some(key) => key,
            None => Self::load_or_generate_key(&base_dir),
        };

        // Load authorized keys
        let authorized_keys = match load_authorized_keys(&base_dir) {
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
        let ca_keys = match load_authorized_cas(&base_dir) {
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
            base_dir,
            active_handlers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            connected_clients: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Load SSH key from file or generate a new one
    ///
    /// # Arguments
    /// * `base_dir` - Base directory containing the .ssh subdirectory
    fn load_or_generate_key(base_dir: &Path) -> PrivateKey {
        // Try to load key from file - use the same path as local discovery for consistency
        let key_path = base_dir.join(".ssh").join("meshkey.pem");

        if key_path.exists() {
            // Load key from file
            let key_data = fs::read(&key_path).expect("Failed to read SSH key file");
            // Check if the file is not empty before trying to parse it
            if !key_data.is_empty() {
                // Try to parse as OpenSSH format first
                if let Ok(key) = PrivateKey::from_openssh(&key_data) {
                    debug!("Loading key from existing file (OpenSSH format)");
                    return key;
                }
                // Try to parse as binary format
                if let Ok(key) = PrivateKey::from_bytes(&key_data) {
                    debug!("Loading key from existing file (binary format)");
                    return key;
                }
                // Note: PEM format support could be added here if needed
                // For now, we'll rely on the existing OpenSSH and binary format support
                // If parsing fails, we'll generate a new key below
                debug!(
                    "Failed to parse existing file in any known format {:?} {:?}",
                    key_path, key_data
                );
            }
        }
        debug!("existing file not found, generating new");

        // Generate new key
        let key = PrivateKey::random(&mut rand::rngs::OsRng, russh::keys::Algorithm::Ed25519)
            .expect("Failed to generate SSH key");

        // Save the generated key to file in OpenSSH format
        std::fs::create_dir_all(key_path.parent().unwrap())
            .expect("Failed to create .ssh directory");

        // Serialize the key properly
        match key.to_openssh(LineEnding::LF) {
            Ok(key_data) => {
                if let Err(e) = fs::write(&key_path, key_data.as_bytes()) {
                    log::warn!("Failed to save SSH key: {}", e);
                } else {
                    // Set proper permissions on private key (0600)
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Ok(metadata) = fs::metadata(&key_path) {
                            let mut perms = metadata.permissions();
                            perms.set_mode(0o600);
                            if let Err(e) = fs::set_permissions(&key_path, perms) {
                                log::warn!("Failed to set key permissions: {}", e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to serialize SSH key: {}", e);
            }
        }

        key
    }

    pub fn get_config(&self) -> server::Config {
        let mut config = server::Config::default();
        config.keys.push(self.keys.clone());
        config.max_auth_attempts = 3;
        config.server_id = russh::SshId::Standard(String::from("SSH-2.0-Rust-SSH-Server"));
        config
    }
}

/// Validate a regular public key against authorized_keys
#[instrument(skip(key_openssh, authorized_keys))]
async fn validate_public_key(
    key_openssh: &str,
    authorized_keys: &Arc<Vec<ssh_key::PublicKey>>,
) -> Result<server::Auth, anyhow::Error> {
    info!("Validating public key: {}", key_openssh);
    // Parse the incoming key from OpenSSH format
    let incoming_key = match ssh_key::PublicKey::from_openssh(key_openssh) {
        Ok(key) => key,
        Err(e) => {
            info!("Failed to parse public key: {}", e);
            return Ok(server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }
    };

    trace!(
        "Comparing against {} authorized keys",
        authorized_keys.len()
    );
    // Compare against all authorized keys using fingerprints
    let incoming_fingerprint = incoming_key.fingerprint(ssh_key::HashAlg::Sha256);

    for (i, authorized_key) in authorized_keys.iter().enumerate() {
        let authorized_fingerprint = authorized_key.fingerprint(ssh_key::HashAlg::Sha256);

        if incoming_fingerprint == authorized_fingerprint {
            info!(
                "Public key authentication successful (match at index {})",
                i
            );
            return Ok(server::Auth::Accept);
        }
    }

    info!("Public key not found in authorized_keys");
    Ok(server::Auth::Reject {
        proceed_with_methods: None,
        partial_success: false,
    })
}

/// Validate a CA-signed certificate
#[instrument(skip(cert_data, ca_keys), fields(user = %user))]
async fn validate_certificate(
    cert_data: &str,
    user: &str,
    ca_keys: &Arc<Vec<ssh_key::PublicKey>>,
) -> Result<server::Auth, anyhow::Error> {
    use ssh_key::Certificate;

    trace!("Parsing certificate data");
    // Parse the certificate
    let certificate = match Certificate::from_openssh(cert_data) {
        Ok(cert) => cert,
        Err(e) => {
            info!("Failed to parse certificate: {}", e);
            return Ok(server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }
    };

    trace!("Building CA fingerprints from {} CA keys", ca_keys.len());
    // Build CA fingerprints from trusted CA keys
    let ca_fingerprints: Vec<ssh_key::Fingerprint> = ca_keys
        .iter()
        .map(|key| key.fingerprint(ssh_key::HashAlg::Sha256))
        .collect();

    if ca_fingerprints.is_empty() {
        info!("No CA keys configured, rejecting certificate");
        return Ok(server::Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        });
    }

    trace!("Validating certificate signature and extensions");
    // Validate certificate (signature, validity window, extensions)
    if let Err(e) = certificate.validate(&ca_fingerprints) {
        info!("Certificate validation failed: {}", e);
        return Ok(server::Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        });
    }

    // Check principals (usernames for user certificates)
    let valid_principals = certificate.valid_principals();
    trace!("Certificate valid principals: {:?}", valid_principals);

    // Empty principals list means valid for any principal
    if !valid_principals.is_empty() {
        let user_matches = valid_principals.iter().any(|p| p == user);

        if !user_matches {
            info!(
                "Certificate principals {:?} do not include user 
išt{}",
                valid_principals, user
            );
            return Ok(server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }
    }

    // Check certificate type (should be user certificate)
    if certificate.cert_type() != ssh_key::certificate::CertType::User {
        info!("Certificate is not a user certificate");
        return Ok(server::Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        });
    }

    info!("Certificate authentication successful for user: {}", user);
    Ok(server::Auth::Accept)
}

#[derive(Debug, Clone)]
struct PtyInfo {
    col_width: u32,
    row_height: u32,
    pix_width: u32,
    pix_height: u32,
}

struct ChannelSession {
    pty: Option<PtyInfo>,
    shell: bool,
    env: HashMap<String, String>,
    // Process handling for PTY/shell sessions
    process: Option<tokio::process::Child>,
    pty_master: Option<std::fs::File>,
}

/// SshHandler is responsible for one TCP connection (real or virtual).
///
/// Still maintain multiple sessions for one client.
#[allow(unused)]
#[derive(Clone)]
pub struct SshHandler {
    id: usize,
    server: SshServer,
    // streams multiplexed on the client TCP connection
    sessions: Arc<Mutex<HashMap<ChannelId, ChannelSession>>>,
    // TCP writers for direct TCP/IP channels
    tcp_writers: Arc<Mutex<HashMap<ChannelId, mpsc::UnboundedSender<Bytes>>>>,
    // Listeners for remote forwarding ((address, port) -> shutdown_sender)
    remote_forward_listeners: Arc<Mutex<HashMap<(String, u32), mpsc::UnboundedSender<()>>>>,

    user: String,
}

/// Handler deals with one SSH connection, after crypto and
/// low level networking.
impl server::Handler for SshHandler {
    type Error = anyhow::Error;

    fn auth_password(
        &mut self,
        user: &str,
        _password: &str,
    ) -> impl std::future::Future<Output = Result<server::Auth, Self::Error>> + Send {
        info!("Password auth attempt for user: {} - REJECTED", user);
        debug!("SSH handler ID: {}", self.id);
        async move {
            Ok(server::Auth::Reject {
                proceed_with_methods: Some((&[MethodKind::PublicKey][..]).into()),
                partial_success: false,
            })
        }
    }

    #[instrument(skip(self, public_key), fields(user = %user))]
    fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> impl std::future::Future<Output = Result<server::Auth, Self::Error>> + Send {
        info!("Public key auth attempt for user: {}", user);
        debug!("SSH handler ID: {}", self.id);

        let authorized_keys = self.server.authorized_keys.clone();
        let ca_keys = self.server.ca_keys.clone();
        let user_str = user.to_string();
        let connected_clients = self.server.connected_clients.clone();
        let handler_id = self.id;

        self.user = user_str.clone();
        // Serialize russh key to OpenSSH format for ssh-key crate
        let key_base64 = public_key.public_key_base64();
        let algorithm = public_key.algorithm();
        let key_type_name = algorithm.as_str();
        let key_openssh = format!("{} {}", key_type_name, key_base64);

        async move {
            info!("Validating public key for user: {}", user);
            // Detect if this is a certificate or regular key
            let auth_result = if key_openssh.contains("-cert-v01@openssh.com") {
                debug!("Validating certificate for user: {}", user);
                let result = validate_certificate(&key_openssh, &user_str, &ca_keys).await;
                result
            } else {
                debug!("Validating public key for user: {}", user);
                let result = validate_public_key(&key_openssh, &authorized_keys).await;
                result
            };

            if let Ok(server::Auth::Accept) = auth_result {
                let mut clients = connected_clients.lock().await;
                let client_info = ConnectedClientInfo {
                    id: handler_id,
                    user: user_str.clone(), // Clone user_str here
                    remote_forward_listeners: Vec::new(),
                    connected_at: SystemTime::now(),
                };
                clients.insert(handler_id, client_info);
            }

            auth_result
        }
    }

    /// This is called when a new stream (called channel) is opened on a client connection
    /// (called stream)
    #[instrument(skip(self, _session), fields(channel_id = ?channel.id()))]
    fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        info!("New session ID: {} channel {:?}", self.id, channel.id());

        let channel_id = channel.id();
        let sessions = self.sessions.clone();
        let handler_id = self.id;

        async move {
            // Create a new session entry for this channel
            let channel_session = ChannelSession {
                pty: None,
                shell: false,
                env: HashMap::new(),
                process: None,
                pty_master: None,
            };

            // Store the session in our sessions map
            let mut sessions_lock = sessions.lock().await;
            sessions_lock.insert(channel_id, channel_session);
            drop(sessions_lock);

            trace!(
                "Created new session for channel {:?} in handler {}",
                channel_id,
                handler_id
            );
            Ok(true)
        }
    }

    #[instrument(skip(self, session), fields(channel_id = ?channel.id(), host_to_connect = %host_to_connect, port_to_connect = %port_to_connect, originator_ip = %originator_ip_address, originator_port = %originator_port))]
    fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_ip_address: &str,
        originator_port: u32,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        info!(
            "Direct TCP/IP connection request: {}:{} from {}:{}",
            host_to_connect, port_to_connect, originator_ip_address, originator_port
        );
        debug!("SSH handler ID: {}", self.id);

        let channel_id = channel.id();
        let sessions = self.sessions.clone();
        let handler_id = self.id;
        let host = host_to_connect.to_string();
        let port = port_to_connect;
        let originator_ip = originator_ip_address.to_string();

        let session_handle = session.handle();

        async move {
            trace!(
                "Processing direct TCP/IP connection for: {}:{} from {}:{}",
                host,
                port,
                originator_ip,
                originator_port
            );

            // Create a new session entry for this channel
            let channel_session = ChannelSession {
                pty: None,
                shell: false,
                env: HashMap::new(),
                process: None,
                pty_master: None,
            };

            // Store the session in our sessions map
            let mut sessions_lock = sessions.lock().await;
            sessions_lock.insert(channel_id, channel_session);
            drop(sessions_lock);

            trace!(
                "Created new direct TCP/IP session for channel {:?} in handler {}",
                channel_id,
                handler_id
            );

            // Establish a TCP connection to the target host:port
            let target_addr = format!("{}:{}", host, port);
            match TcpStream::connect(&target_addr).await {
                Ok(tcp_stream) => {
                    trace!("Successfully connected to target {}:{}", host, port);

                    // Set up bidirectional data forwarding between SSH channel and TCP connection
                    let (mut tcp_reader, tcp_writer) = tcp_stream.into_split();
                    let channel_id = channel_id;

                    // Store the TCP writer for SSH to TCP forwarding
                    let tcp_writers = self.tcp_writers.clone();
                    let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                    {
                        let mut writers = tcp_writers.lock().await;
                        writers.insert(channel_id, tx);
                    }

                    // Spawn task to forward data from TCP to SSH channel
                    let session_handle_clone = session_handle.clone();
                    let tcp_writers_clone = tcp_writers.clone();
                    tokio::spawn(async move {
                        let mut buffer = [0; 8192];
                        loop {
                            match tcp_reader.read(&mut buffer).await {
                                Ok(0) => {
                                    // EOF - connection closed
                                    trace!("TCP connection closed for channel {:?}", channel_id);
                                    break;
                                }
                                Ok(n) => {
                                    info!("TCP forwarding got {}", n);
                                    // Forward data to SSH channel
                                    if let Err(e) = session_handle_clone
                                        .data(channel_id, (&buffer[..n]).into())
                                        .await
                                    {
                                        error!(
                                            "Failed to send data to SSH channel {:?}: {:?}",
                                            channel_id, e
                                        );
                                        break;
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "Failed to read from TCP connection for channel {:?}: {}",
                                        channel_id, e
                                    );
                                    break;
                                }
                            }
                        }
                        // Close the channel when TCP connection closes
                        let _ = session_handle_clone.close(channel_id).await;

                        // Clean up the TCP writer
                        let mut writers = tcp_writers_clone.lock().await;
                        writers.remove(&channel_id);
                    });

                    // Spawn task to forward data from SSH channel to TCP connection
                    let tcp_writers_clone2 = tcp_writers.clone();
                    tokio::spawn(async move {
                        let mut rx = rx;
                        let mut tcp_writer = tcp_writer;
                        while let Some(data) = rx.recv().await {
                            info!("SSHd received data from target server");
                            if let Err(e) = tcp_writer.write_all(&data).await {
                                error!(
                                    "Failed to write to TCP connection for channel {:?}: {}",
                                    channel_id, e
                                );
                                break;
                            }
                            if let Err(e) = tcp_writer.flush().await {
                                error!(
                                    "Failed to write to TCP connection for channel {:?}: {}",
                                    channel_id, e
                                );
                                break;
                            }
                        }
                        // Clean up the TCP writer
                        let mut writers = tcp_writers_clone2.lock().await;
                        writers.remove(&channel_id);
                    });

                    Ok(true)
                }
                Err(e) => {
                    error!("Failed to connect to target {}:{}: {}", host, port, e);
                    Ok(false) // Reject the channel if we can't connect
                }
            }
        }
    }

    #[instrument(skip(self, _session), fields(channel_id = ?_channel.id(), host_to_connect = %_host_to_connect, port_to_connect = %_port_to_connect, originator_ip = %_originator_ip_address, originator_port = %_originator_port))]
    fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_ip_address: &str,
        _originator_port: u32,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        error!("Client-initiated forwarded-tcpip channel is not supported.");
        async { Ok(false) }
    }

    #[instrument(skip(self, session), fields(channel_id = ?channel, data_len = data.len()))]
    fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let command = String::from_utf8_lossy(data).to_string();
        info!("Executing command: {}", command);
        debug!("SSH handler ID: {}", self.id);

        let channel_id = channel;
        let command_str = command.clone();

        async move {
            trace!("Executing command in shell: {}", command_str);
            // Execute the command and capture output
            let output = Command::new("sh")
                .arg("-c")
                .arg(&command_str)
                .output()
                .await
                .map_err(anyhow::Error::new)?;

            debug!(
                "Command execution completed with status: {:?}",
                output.status
            );

            // Send the command output back to the client
            if !output.stdout.is_empty() {
                trace!("Sending stdout ({} bytes)", output.stdout.len());
                session
                    .data(channel_id, output.stdout.into())
                    .map_err(anyhow::Error::new)?;
            }

            if !output.stderr.is_empty() {
                trace!("Sending stderr ({} bytes)", output.stderr.len());
                session
                    .extended_data(channel_id, 1, output.stderr.into())
                    .map_err(anyhow::Error::new)?;
            }

            // Send exit status
            let exit_code = output.status.code().unwrap_or(0) as u32;
            trace!("Sending exit status: {}", exit_code);
            let _ = session.exit_status_request(channel_id, exit_code);

            let _ = session.close(channel_id);

            Ok(())
        }
    }

    #[instrument(skip(self, session), fields(channel_id = ?channel, data_len = data.len()))]
    fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let _data_str = String::from_utf8_lossy(data).to_string();
        trace!(
            "Received data on channel {:?}: {} bytes",
            channel,
            data.len()
        );
        debug!("SSH handler ID: {}", self.id);

        // Check if this is a direct TCP/IP channel and forward data to the TCP connection
        let tcp_writers = self.tcp_writers.clone();
        let data_vec = data.to_vec();
        let channel_id = channel;
        let session_handle = session.handle();

        async move {
            // Check if we have a TCP writer for this channel
            let writers = tcp_writers.lock().await;
            if let Some(tx) = writers.get(&channel_id) {
                // Forward data to the TCP connection or PTY
                trace!(
                    "Forwarding {} bytes from SSH channel {:?}",
                    data_vec.len(),
                    channel_id
                );
                if let Err(e) = tx.send(Bytes::from(data_vec.clone())) {
                    error!("Failed to send data for channel {:?}: {}", channel_id, e);
                }
            } else {
                // Not a direct TCP/IP channel, echo the data back for other types of channels
                trace!(
                    "Echoing data back ({} bytes) for non-TCP channel {:?}",
                    data_vec.len(),
                    channel_id
                );
                let _ = session_handle.data(channel_id, data_vec.into()).await;
            }
            Ok(())
        }
    }

    #[instrument(skip(self, _session), fields(channel_id = ?channel))]
    fn shell_request(
        &mut self,
        channel: ChannelId,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        info!("Shell request for channel {:?}", channel);
        debug!("SSH handler ID: {}", self.id);

        let sessions = self.sessions.clone();
        let tcp_writers = self.tcp_writers.clone();
        let channel_id = channel;

        async move {
            // Update the session to indicate it has a shell request
            let mut sessions_lock = sessions.lock().await;
            let pty_option = if let Some(channel_session) = sessions_lock.get_mut(&channel_id) {
                channel_session.shell = true;
                // If PTY was already requested, we have its dimensions stored.
                let winsize = channel_session
                    .pty
                    .as_ref()
                    .map(|pty_info| nix::libc::winsize {
                        ws_row: pty_info.row_height as u16,
                        ws_col: pty_info.col_width as u16,
                        ws_xpixel: pty_info.pix_width as u16,
                        ws_ypixel: pty_info.pix_height as u16,
                    });

                let pty = openpty(None, winsize.as_ref(), None)
                    .map_err(|e| anyhow::Error::msg(format!("{:?}", e)))?;
                channel_session.pty_master = Some(pty.0);
                // Store PTY info for later if needed (not used further here).
                // Spawn a shell attached to the slave side.
                let slave_fd = pty.1.as_raw_fd();
                // Safety: we take ownership of raw fds.
                let slave_file = &pty.1;
                // Set up the command.
                let mut cmd = Command::new("/bin/sh");
                cmd.env("TERM", "xterm-256color");
                for (key, value) in &channel_session.env {
                    cmd.env(key, value);
                }
                cmd.stdin(
                    slave_file
                        .try_clone()
                        .map_err(|e| anyhow::Error::msg(format!("{:?}", e)))?,
                );
                cmd.stdout(
                    slave_file
                        .try_clone()
                        .map_err(|e| anyhow::Error::msg(format!("{:?}", e)))?,
                );
                cmd.stderr(
                    slave_file
                        .try_clone()
                        .map_err(|e| anyhow::Error::msg(format!("{:?}", e)))?,
                );
                // Ensure the child becomes session leader and has controlling terminal.
                unsafe {
                    cmd.pre_exec(move || {
                        // Create a new session.
                        setsid().map_err(|e| std::io::Error::other(e))?;
                        // Set the slave PTY as the controlling terminal.
                        if ioctl(slave_fd, TIOCSCTTY, 0) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        // Duplicate slave onto stdin/stdout/stderr.
                        dup2(slave_fd, 0).map_err(|e| std::io::Error::other(e))?;
                        dup2(slave_fd, 1).map_err(|e| std::io::Error::other(e))?;
                        dup2(slave_fd, 2).map_err(|e| std::io::Error::other(e))?;
                        Ok(())
                    });
                }
                let child = cmd.spawn().map_err(|e| anyhow::anyhow!(e))?;
                // Save the child process and its stdin for later cleanup.
                channel_session.process = Some(child);
                // Return the PTY for I/O handling.
                Some(pty.1)
            } else {
                trace!(
                    "No session found for channel {:?} when processing shell request",
                    channel_id
                );
                None
            };
            drop(sessions_lock);

            // If we have a PTY, set up I/O forwarding.
            if let Some(slave) = pty_option {
                let sessions_lock = sessions.lock().await;
                let master = sessions_lock
                    .get(&channel_id)
                    .unwrap()
                    .pty_master
                    .as_ref()
                    .unwrap();
                let master_fd = master.as_raw_fd();
                trace!("PTY created with master fd {}", master_fd);

                // Duplicate the master FD twice so we have independent read and write FDs
                // This is necessary because PTYs are character devices and splitting a single
                // File handle doesn't work correctly for bidirectional I/O
                use std::os::unix::io::FromRawFd;
                let master_fd_read = unsafe { nix::libc::dup(master_fd) };
                if master_fd_read < 0 {
                    return Err(anyhow::Error::msg(
                        "Failed to duplicate master FD for reading",
                    ));
                }
                let master_fd_write = unsafe { nix::libc::dup(master_fd) };
                if master_fd_write < 0 {
                    unsafe {
                        nix::libc::close(master_fd_read);
                    }
                    return Err(anyhow::Error::msg(
                        "Failed to duplicate master FD for writing",
                    ));
                }

                // Now create File objects from the duplicated FDs
                let master_read_file = unsafe { std::fs::File::from_raw_fd(master_fd_read) };
                let master_write_file = unsafe { std::fs::File::from_raw_fd(master_fd_write) };

                let mut master_read = tokio::fs::File::from_std(master_read_file);
                let mut master_write = tokio::fs::File::from_std(master_write_file);
                drop(slave);

                // Get a handle to the SSH channel for sending data back.
                let session_handle = _session.handle();
                let ch_id = channel_id;
                // Spawn task that reads from PTY and writes to the SSH client.
                tokio::spawn(async move {
                    trace!("Starting PTY to SSH reader task for channel {:?}", ch_id);
                    let mut buf = [0u8; 8192];
                    loop {
                        match master_read.read(&mut buf).await {
                            Ok(0) => {
                                // EOF - connection closed
                                trace!("PTY closed (EOF) for channel {:?}", ch_id);
                                let _ = session_handle.close(ch_id).await;
                                break;
                            }
                            Ok(n) => {
                                trace!("Read {} bytes from PTY", n);
                                if session_handle
                                    .data(ch_id, (&buf[..n]).into())
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Err(e)
                                if e.kind() == std::io::ErrorKind::Other
                                    || e.raw_os_error() == Some(5) =>
                            {
                                // EIO (error 5) happens when the PTY slave closes (shell exits)
                                // This is expected and not an error condition
                                trace!("PTY closed for channel {:?}", ch_id);
                                let _ = session_handle.close(ch_id).await;
                                break;
                            }
                            Err(e) => {
                                error!("Error reading PTY for channel {:?}: {}", ch_id, e);
                                break;
                            }
                        }
                    }
                    trace!("PTY reader task ended for channel {:?}", ch_id);
                });

                // Now forward data from SSH client -> PTY. Store writer in the tcp_writers map so that data() can use it.
                let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();
                {
                    let mut writers = tcp_writers.lock().await;
                    writers.insert(ch_id, tx);
                }
                // Spawn a task that consumes data from the channel (via the writer) and writes to the PTY master.
                tokio::spawn(async move {
                    info!(
                        "PTY WRITER: Starting SSH to PTY writer task for channel {:?}",
                        ch_id
                    );
                    while let Some(data) = rx.recv().await {
                        info!(
                            "PTY WRITER: Received from SSH, writing {} bytes to PTY: {:?}",
                            data.len(),
                            data
                        );
                        if let Err(e) = master_write.write_all(&data).await {
                            error!(
                                "PTY WRITER: Error writing to PTY for channel {:?}: {}",
                                ch_id, e
                            );
                            break;
                        }
                        info!("PTY WRITER: Write successful, flushing...");
                        if let Err(e) = master_write.flush().await {
                            error!(
                                "PTY WRITER: Error flushing PTY for channel {:?}: {}",
                                ch_id, e
                            );
                            break;
                        }
                        info!("PTY WRITER: Flush successful for {} bytes", data.len());
                    }
                    info!("PTY WRITER: SSH to PTY task ended for channel {:?}", ch_id);
                });
            }

            Ok(())
        }
    }

    #[instrument(skip(self, _session), fields(channel_id = ?channel, term = %term))]
    fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        info!(
            "PTY request for channel {:?}: term={}, {}x{} ({}x{} px), modes: {} entries",
            channel,
            term,
            col_width,
            row_height,
            pix_width,
            pix_height,
            modes.len()
        );

        let sessions = self.sessions.clone();
        let channel_id = channel;
        let term = term.to_string();

        if DEBUG_PTY {
            // Log PTY modes for debugging
            for (mode, value) in modes {
                trace!("PTY mode: {:?} = {}", mode, value);
            }
        }

        async move {
            // Update the session with PTY information
            let mut sessions_lock = sessions.lock().await;
            if let Some(channel_session) = sessions_lock.get_mut(&channel_id) {
                channel_session.pty = Some(PtyInfo {
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                });
                trace!("Updated PTY info for channel {:?}", channel_id);

                // If PTY is already open, update its size.
                if let Some(master) = &channel_session.pty_master {
                    let mut winsize = nix::libc::winsize {
                        ws_row: row_height as u16,
                        ws_col: col_width as u16,
                        ws_xpixel: pix_width as u16,
                        ws_ypixel: pix_height as u16,
                    };
                    unsafe {
                        nix::libc::ioctl(master.as_raw_fd(), nix::libc::TIOCSWINSZ, &mut winsize);
                    }
                }
            } else {
                trace!(
                    "No session found for channel {:?} when processing PTY request",
                    channel_id
                );
            }
            drop(sessions_lock);

            // We're accepting PTY requests but actual terminal emulation
            // would need to be implemented based on these parameters
            trace!("Processing PTY request with terminal info");
            Ok(())
        }
    }

    #[instrument(skip(self, _session), fields(channel_id = ?channel))]
    fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        info!(
            "Env request for channel {:?}: {}={}",
            channel, variable_name, variable_value
        );

        let sessions = self.sessions.clone();
        let channel_id = channel;
        let variable_name = variable_name.to_string();
        let variable_value = variable_value.to_string();

        async move {
            let mut sessions_lock = sessions.lock().await;
            if let Some(channel_session) = sessions_lock.get_mut(&channel_id) {
                channel_session.env.insert(variable_name, variable_value);
            }
            drop(sessions_lock);
            Ok(())
        }
    }

    #[instrument(skip(self, _session), fields(channel_id = ?channel))]
    fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        info!(
            "Window change request for channel {:?}: {}x{} ({}x{} px)",
            channel, col_width, row_height, pix_width, pix_height
        );

        let sessions = self.sessions.clone();
        let channel_id = channel;

        async move {
            // Update the session with the new window size
            let mut sessions_lock = sessions.lock().await;
            if let Some(channel_session) = sessions_lock.get_mut(&channel_id) {
                if let Some(pty) = &mut channel_session.pty {
                    pty.col_width = col_width;
                    pty.row_height = row_height;
                    pty.pix_width = pix_width;
                    pty.pix_height = pix_height;
                }
                if let Some(master) = &channel_session.pty_master {
                    trace!("Updating window size for channel {:?}", channel_id);
                    let mut winsize = nix::libc::winsize {
                        ws_row: row_height as u16,
                        ws_col: col_width as u16,
                        ws_xpixel: pix_width as u16,
                        ws_ypixel: pix_height as u16,
                    };
                    unsafe {
                        nix::libc::ioctl(master.as_raw_fd(), nix::libc::TIOCSWINSZ, &mut winsize);
                    }
                }
            }
            drop(sessions_lock);

            // We're accepting PTY requests but actual terminal emulation
            // would need to be implemented based on these parameters
            trace!("Processing PTY request with terminal info");
            Ok(())
        }
    }

    #[instrument(skip(self, session), fields(address = %address, port = %*port))]
    fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let session_handle = session.handle();
        let tcp_writers = self.tcp_writers.clone();
        let remote_forward_listeners = self.remote_forward_listeners.clone();
        let bind_addr = address.to_string();
        let bind_port = *port;

        let fut = async move {
            let listen_addr = format!("{}:{}", bind_addr, bind_port);
            let listener = match tokio::net::TcpListener::bind(&listen_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind to {}: {}", listen_addr, e);
                    return (Err(anyhow::Error::new(e)), 0);
                }
            };

            let actual_port = listener.local_addr().unwrap().port();
            info!("Started listening on {}:{}", bind_addr, actual_port);

            // Channel to signal shutdown
            let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();

            {
                let mut listeners = remote_forward_listeners.lock().await;
                listeners.insert((bind_addr.clone(), bind_port), shutdown_tx);
            }

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            match accepted {
                                Ok((tcp_stream, originator_addr)) => {
                                    info!("Accepted connection from {}", originator_addr);
                                    let session_handle_clone = session_handle.clone();
                                    let tcp_writers_clone = tcp_writers.clone();
                                    let bind_addr_clone = bind_addr.clone();

                                    tokio::spawn(async move {
                                        // Open a forwarded-tcpip channel to the client
                                        let channel = match session_handle_clone.channel_open_forwarded_tcpip(
                                            &bind_addr_clone,
                                            actual_port as u32,
                                            &originator_addr.ip().to_string(),
                                            originator_addr.port() as u32,
                                        ).await {
                                            Ok(channel) => channel,
                                            Err(e) => {
                                                error!("Failed to open forwarded-tcpip channel: {}", e);
                                                return;
                                            }
                                        };
                                        let channel_id = channel.id();
                                        info!("Opened forwarded-tcpip channel {:?}", channel_id);

                                        // Set up bidirectional data forwarding
                                        let (mut tcp_reader, tcp_writer) = tcp_stream.into_split();

                                        // Store the TCP writer for SSH to TCP forwarding
                                        let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();
                                        {
                                            let mut writers = tcp_writers_clone.lock().await;
                                            writers.insert(channel_id, tx);
                                        }

                                        // Spawn task to forward data from TCP to SSH channel
                                        let session_handle_clone2 = session_handle_clone.clone();
                                        let tcp_writers_clone2 = tcp_writers_clone.clone();
                                        tokio::spawn(async move {
                                            let mut buffer = [0; 8192];
                                            loop {
                                                match tcp_reader.read(&mut buffer).await {
                                                    Ok(0) => {
                                                        trace!("TCP connection closed for channel {:?}", channel_id);
                                                        break;
                                                    }
                                                    Ok(n) => {
                                                        if let Err(e) = session_handle_clone2.data(channel_id, (&buffer[..n]).into()).await {
                                                            error!("Failed to send data to SSH channel {:?}: {:?}", channel_id, e);
                                                            break;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!("Failed to read from TCP connection for channel {:?}: {}", channel_id, e);
                                                        break;
                                                    }
                                                }
                                            }
                                            let _ = session_handle_clone2.close(channel_id).await;
                                            let mut writers = tcp_writers_clone2.lock().await;
                                            writers.remove(&channel_id);
                                        });

                                        // Spawn task to forward data from SSH channel to TCP connection
                                        let tcp_writers_clone3 = tcp_writers_clone.clone();
                                        tokio::spawn(async move {
                                            let mut tcp_writer = tcp_writer;
                                            while let Some(data) = rx.recv().await {
                                                if let Err(e) = tcp_writer.write_all(&data).await {
                                                    error!("Failed to write to TCP connection for channel {:?}: {}", channel_id, e);
                                                    break;
                                                }
                                            }
                                            let mut writers = tcp_writers_clone3.lock().await;
                                            writers.remove(&channel_id);
                                        });
                                    });
                                }
                                Err(e) => {
                                    error!("Error accepting connection: {}", e);
                                    break;
                                }
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            info!("Stopping listener for {}:{}", bind_addr, actual_port);
                            break;
                        }
                    }
                }
                // Cleanup
                let mut listeners = remote_forward_listeners.lock().await;
                listeners.remove(&(bind_addr, bind_port));
            });

            (Ok(()), actual_port)
        };

        async move {
            let (result, actual_port) = fut.await;
            if result.is_ok() {
                *port = actual_port as u32;
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    #[instrument(skip(self, _session), fields(address = %address, port = %port))]
    fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        info!(
            "Request to cancel TCP/IP forwarding for {}:{}",
            address, port
        );
        let remote_forward_listeners = self.remote_forward_listeners.clone();
        let address = address.to_string();

        async move {
            let mut listeners = remote_forward_listeners.lock().await;
            if let Some(shutdown_tx) = listeners.remove(&(address.clone(), port)) {
                // Sending a message will cause the listening task to break its loop and exit.
                let _ = shutdown_tx.send(());
                info!("Cancelled TCP/IP forwarding for {}:{}", address, port);
                Ok(true)
            } else {
                log::warn!(
                    "No active forwarding found for {}:{} to cancel",
                    address,
                    port
                );
                Ok(false)
            }
        }
    }

    #[instrument(skip(self, _session), fields(channel_id = ?channel))]
    fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        info!("Channel EOF: stream: {:?} client: {}", channel, self.id);
        let tcp_writers = self.tcp_writers.clone();
        let channel_id = channel;
        async move {
            let mut writers = tcp_writers.lock().await;
            if writers.remove(&channel_id).is_some() {
                debug!("Removed writer for channel {:?} after EOF", channel_id);
            }
            Ok(())
        }
    }

    #[instrument(skip(self, _session), fields(channel_id = ?channel))]
    fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        info!("Channel closed: stream {:?} client {}", channel, self.id);
        debug!("SSH handler ID: client {}", self.id);

        let sessions = self.sessions.clone();
        let tcp_writers = self.tcp_writers.clone();
        let connected_clients = self.server.connected_clients.clone();
        let handler_id = self.id;
        let channel_id = channel;

        async move {
            // Remove the session from our sessions map and clean up PTY process if any
            let mut sessions_lock = sessions.lock().await;
            if let Some(mut removed_session) = sessions_lock.remove(&channel_id) {
                trace!(
                    "Removed session for channel {:?} from handler {}",
                    channel_id,
                    handler_id
                );
                // If a PTY process was spawned, kill it.
                if let Some(mut child) = removed_session.process.take() {
                    // Attempt graceful termination, then force kill if needed.
                    let _ = child.kill().await;
                }
                drop(sessions_lock);
                trace!("Cleaned up session data for channel {:?}", channel_id);
            } else {
                trace!(
                    "No session found for channel {:?} in handler {}",
                    channel_id,
                    handler_id
                );
            }

            // Remove the writer (PTY or TCP) for this channel if it exists
            let mut writers_lock = tcp_writers.lock().await;
            if let Some(_removed_writer) = writers_lock.remove(&channel_id) {
                trace!("Removed writer for channel {:?}", channel_id);
            } else {
                trace!("No writer found for channel {:?}", channel_id);
            }

            // Remove the client from the connected_clients map
            let mut clients = connected_clients.lock().await;
            clients.remove(&handler_id);
            eprintln!(
                "DEBUG: Client {} removed. Connected clients remaining: {:?}",
                handler_id,
                clients.keys().collect::<Vec<_>>()
            );

            Ok(())
        }
    }

    #[instrument(skip(self, session), fields(channel_id = ?channel, name = %name))]
    fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        info!("Subsystem request: {}", name);
        let channel_id = channel;
        let subsystem_name = name.to_string();
        let tcp_writers = self.tcp_writers.clone();
        let session_handle = session.handle();

        async move {
            if subsystem_name == "sftp" {
                let sftp_server_path = "/usr/lib/openssh/sftp-server";
                if !std::path::Path::new(sftp_server_path).exists() {
                    error!("SFTP server binary not found at {}", sftp_server_path);
                    let _ = session_handle.channel_failure(channel_id).await;
                    return Ok(());
                }

                info!(
                    "Spawning SFTP server: {} in {:?}",
                    sftp_server_path, self.server.base_dir
                );
                let mut cmd = Command::new(sftp_server_path);
                cmd.current_dir(&self.server.base_dir)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());

                let mut child = cmd.spawn().map_err(|e| anyhow::anyhow!(e))?;
                let mut stdin = child.stdin.take().unwrap();
                let mut stdout = child.stdout.take().unwrap();
                let mut stderr = child.stderr.take().unwrap();

                // Forward SFTP stdout -> SSH data
                let session_handle_clone = session_handle.clone();
                tokio::spawn(async move {
                    debug!("SFTP stdout -> SSH reader task started");
                    let mut buf = [0u8; 8192];
                    loop {
                        match stdout.read(&mut buf).await {
                            Ok(0) => {
                                debug!("SFTP stdout reached EOF");
                                break;
                            }
                            Ok(n) => {
                                trace!("Read {} bytes from SFTP stdout, sending to SSH", n);
                                if session_handle_clone
                                    .data(channel_id, (&buf[..n]).into())
                                    .await
                                    .is_err()
                                {
                                    error!("Failed to send SFTP data to SSH channel");
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("Error reading SFTP stdout: {}", e);
                                break;
                            }
                        }
                    }
                    debug!("SFTP stdout -> SSH reader task ended");
                    let _ = session_handle_clone.close(channel_id).await;
                });

                // Forward SFTP stderr -> SSH extended data
                let session_handle_clone2 = session_handle.clone();
                tokio::spawn(async move {
                    debug!("SFTP stderr -> SSH reader task started");
                    let mut buf = [0u8; 8192];
                    loop {
                        match stderr.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if session_handle_clone2
                                    .extended_data(channel_id, 1, (&buf[..n]).into())
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    debug!("SFTP stderr -> SSH reader task ended");
                });

                // Forward SSH data -> SFTP stdin
                let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();
                {
                    let mut writers = tcp_writers.lock().await;
                    writers.insert(channel_id, tx);
                }

                tokio::spawn(async move {
                    debug!("SSH -> SFTP stdin writer task started");
                    while let Some(data) = rx.recv().await {
                        trace!("Writing {} bytes to SFTP stdin", data.len());
                        if let Err(e) = stdin.write_all(&data).await {
                            error!("Error writing to SFTP stdin: {}", e);
                            break;
                        }
                        if let Err(e) = stdin.flush().await {
                            error!("Error flushing SFTP stdin: {}", e);
                            break;
                        }
                    }
                    debug!("SSH -> SFTP stdin writer task ended");
                });

                // Monitor child process exit
                let session_handle_clone3 = session_handle.clone();
                tokio::spawn(async move {
                    debug!("SFTP process monitor task started");
                    match child.wait().await {
                        Ok(status) => {
                            info!("SFTP server exited with status: {:?}", status);
                            let exit_code = status.code().unwrap_or(0) as u32;
                            let _ = session_handle_clone3
                                .exit_status_request(channel_id, exit_code)
                                .await;
                        }
                        Err(e) => {
                            error!("Error waiting for SFTP server: {}", e);
                        }
                    }
                    debug!("SFTP process monitor task ended");
                });

                info!("SFTP subsystem request accepted and handlers spawned");
                let _ = session_handle.channel_success(channel_id).await;
                Ok(())
            } else {
                error!("Unsupported subsystem: {}", subsystem_name);
                let _ = session_handle.channel_failure(channel_id).await;
                Ok(())
            }
        }
    }
}

impl server::Server for SshServer {
    type Handler = SshHandler;

    #[instrument(skip(self))]
    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        let mut id = self.id_counter.lock().unwrap();
        *id += 1;
        let handler = SshHandler {
            id: *id,
            server: self.clone(),
            sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            tcp_writers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            remote_forward_listeners: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            user: String::new(),
        };

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

// TODO: hook this method into the app
// TODO: add pmon, ws methods into the app
// TODO: add monitoring from ws create.


// ============================================================================
// SSH CA Management Functions
// ============================================================================

/// Generate a new Ed25519 CA keypair for SSH certificate signing
pub fn generate_ca_keypair() -> Result<(ssh_key::PrivateKey, ssh_key::PublicKey), anyhow::Error> {
    use ssh_key::Algorithm;

    let private_key = ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519)?;
    let public_key = private_key.public_key().clone();

    Ok((private_key, public_key))
}

/// Save CA keypair to baseDir/.ssh/id_ca and baseDir/.ssh/id_ca.pub
///
/// # Arguments
/// * `private_key` - The private key to save
/// * `public_key` - The public key to save
/// * `base_dir` - Base directory containing the .ssh subdirectory
pub fn save_ca_keypair(
    private_key: &ssh_key::PrivateKey,
    public_key: &ssh_key::PublicKey,
    base_dir: &Path,
) -> Result<(), anyhow::Error> {
    let ssh_dir = base_dir.join(".ssh");

    // Create .ssh directory if it doesn't exist
    fs::create_dir_all(&ssh_dir)?;

    let private_key_path = ssh_dir.join("id_ca");
    let public_key_path = ssh_dir.join("id_ca.pub");

    // Save private key in OpenSSH format
    let private_key_pem = private_key.to_openssh(LineEnding::LF)?;
    fs::write(&private_key_path, private_key_pem.as_bytes())?;

    // Set proper permissions on private key (0600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&private_key_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&private_key_path, perms)?;
    }

    // Save public key in OpenSSH format
    let public_key_str = public_key.to_openssh()?;
    fs::write(&public_key_path, public_key_str.as_bytes())?;

    info!(
        "CA keypair saved to {} and {}",
        private_key_path.display(),
        public_key_path.display()
    );
    Ok(())
}

/// Load CA private key from baseDir/.ssh/id_ca
///
/// # Arguments
/// * `base_dir` - Base directory containing the .ssh subdirectory
pub fn load_ca_private_key(base_dir: &Path) -> Result<ssh_key::PrivateKey, anyhow::Error> {
    let private_key_path = base_dir.join(".ssh").join("id_ca");

    if !private_key_path.exists() {
        return Err(anyhow::Error::msg(format!(
            "CA private key not found at {}. Run generate_ca_keypair() first.",
            private_key_path.display()
        )));
    }

    let private_key_data = fs::read_to_string(&private_key_path)?;
    let private_key = ssh_key::PrivateKey::from_openssh(&private_key_data)?;

    Ok(private_key)
}

/// Sign a user's public key with the CA to create an SSH certificate
///
/// # Arguments
/// * `ca_private_key` - The CA's private key for signing
/// * `user_public_key` - The user's public key to be certified
/// * `principals` - List of principals (usernames) this certificate is valid for
/// * `validity_days` - Number of days the certificate is valid from now
pub fn sign_user_certificate(
    ca_private_key: &ssh_key::PrivateKey,
    user_public_key: &ssh_key::PublicKey,
    principals: Vec<String>,
    validity_days: u64,
) -> Result<ssh_key::Certificate, anyhow::Error> {
    use ssh_key::certificate::{Builder, CertType};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Calculate validity window
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let valid_after = now;
    let valid_before = now + (validity_days * 24 * 60 * 60);

    // Build certificate
    let mut builder = Builder::new_with_random_nonce(
        &mut rand::rngs::OsRng,
        user_public_key.clone(),
        valid_after,
        valid_before,
    )?;

    builder.cert_type(CertType::User)?;

    // Add principals
    for principal in principals {
        builder.valid_principal(principal)?;
    }

    // Sign the certificate
    let certificate = builder.sign(ca_private_key)?;

    Ok(certificate)
}

/// Save an SSH certificate to a file
pub fn save_certificate(
    certificate: &ssh_key::Certificate,
    output_path: &Path,
) -> Result<(), anyhow::Error> {
    let cert_str = certificate.to_openssh()?;
    fs::write(output_path, cert_str.as_bytes())?;
    info!("Certificate saved to {}", output_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    #[test]
    fn test_get_port_from_env() {
        // Test with default value
        let default_port = 1234;
        let random_var = "NONEXISTENT_VAR";
        assert_eq!(get_port_from_env(random_var, default_port), default_port);

        // Test with environment variable set
        let test_port = 5678;
        let test_var = "TEST_PORT";
        std::env::set_var(test_var, test_port.to_string());
        assert_eq!(get_port_from_env(test_var, default_port), test_port);

        // Cleanup
        std::env::remove_var(test_var);
    }

    #[test]
    fn test_ssh_server_creation() {
        let base_dir = env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"));
        let key = PrivateKey::random(&mut rand::rngs::OsRng, russh::keys::Algorithm::Ed25519)
            .expect("Failed to generate test key");
        let server = SshServer::new(42, Some(key), base_dir);
        let config = server.get_config();

        // Verify some configuration settings
        assert_eq!(config.keys.len(), 1);
        match &config.server_id {
            russh::SshId::Standard(id) => assert_eq!(id, "SSH-2.0-Rust-SSH-Server"),
            _ => panic!("Unexpected server ID format"),
        }
        // connection_timeout field was removed in this version
    }

    #[test]
    fn test_load_or_generate_key_persistence() {
        // Create a temporary directory for testing
        let temp_dir = tempfile::Builder::new()
            .prefix("ssh_key_test")
            .tempdir()
            .expect("Failed to create temp dir");
        let base_dir = temp_dir.path().to_path_buf();

        // First call should generate a new key
        let first_key = SshServer::load_or_generate_key(&base_dir);

        // Verify the key file was created
        let key_path = base_dir.join(".ssh").join("meshkey.pem");
        assert!(key_path.exists(), "Key file should be created");

        // Second call should load the same key
        let second_key = SshServer::load_or_generate_key(&base_dir);

        // The keys should be identical
        assert_eq!(
            first_key.to_bytes().expect("Failed to serialize first key"),
            second_key
                .to_bytes()
                .expect("Failed to serialize second key"),
            "Keys should be identical after reload"
        );
    }
}

/// Function to get port from environment variable or use default
/// Helper for main.
pub fn get_port_from_env(var_name: &str, default: u16) -> u16 {
    std::env::var(var_name)
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(default)
}

/// Load authorized public keys from baseDir/.ssh/authorized_keys
///
/// # Arguments
/// * `base_dir` - Base directory containing the .ssh subdirectory
///
/// Returns an empty vector if the file doesn't exist.
/// Malformed lines are logged and skipped.
fn load_authorized_keys(base_dir: &Path) -> Result<Vec<ssh_key::PublicKey>, anyhow::Error> {
    let path = base_dir.join(AUTHORIZED_KEYS_PATH);

    // Return empty vector if file doesn't exist (not an error)
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content =
        fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;

    parse_authorized_keys_content(&content)
}

/// Parse authorized_keys file content
fn parse_authorized_keys_content(content: &str) -> Result<Vec<ssh_key::PublicKey>, anyhow::Error> {
    let mut keys = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse the line as an OpenSSH public key
        match ssh_key::PublicKey::from_openssh(line) {
            Ok(key) => keys.push(key),
            Err(e) => {
                // Log warning but continue (don't fail on malformed lines)
                log::warn!(
                    "Failed to parse authorized_keys line {}: {}",
                    line_num + 1,
                    e
                );
            }
        }
    }

    Ok(keys)
}

/// Load CA public keys from baseDir/.ssh/authorized_cas
///
/// # Arguments
/// * `base_dir` - Base directory containing the .ssh subdirectory
///
/// Returns an empty vector if the file doesn't exist.
/// Malformed lines are logged and skipped.
fn load_authorized_cas(base_dir: &Path) -> Result<Vec<ssh_key::PublicKey>, anyhow::Error> {
    let path = base_dir.join(AUTHORIZED_CAS_PATH);

    // Return empty vector if file doesn't exist
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content =
        fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;

    parse_authorized_cas_content(&content)
}

/// Parse authorized_cas file content
fn parse_authorized_cas_content(content: &str) -> Result<Vec<ssh_key::PublicKey>, anyhow::Error> {
    let mut ca_keys = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // OpenSSH format with @cert-authority marker:
        // @cert-authority [principals="..."] keytype base64-key [comment]
        if !line.starts_with("@cert-authority") && !line.starts_with("cert-authority") {
            log::warn!(
                "authorized_cas line {} missing cert-authority marker, skipping",
                line_num + 1
            );
            continue;
        }

        // Find the key part (after @cert-authority and optional principals)
        let parts: Vec<&str> = line.split_whitespace().collect();

        // Find where the actual key starts (skip @cert-authority and principals=...)
        let mut key_start = 1; // Start after @cert-authority
        while key_start < parts.len() {
            if parts[key_start].starts_with("principals=") || parts[key_start] == "*" {
                key_start += 1;
            } else {
                break;
            }
        }

        if key_start >= parts.len() {
            log::warn!("authorized_cas line {} has no key data", line_num + 1);
            continue;
        }

        // Reconstruct the key line (keytype base64-key comment)
        let key_line = parts[key_start..].join(" ");

        match ssh_key::PublicKey::from_openssh(&key_line) {
            Ok(key) => ca_keys.push(key),
            Err(e) => {
                log::warn!(
                    "Failed to parse authorized_cas line {}: {}",
                    line_num + 1,
                    e
                );
            }
        }
    }

    Ok(ca_keys)
}
