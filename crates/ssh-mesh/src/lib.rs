#[cfg(feature = "test-utils")]
pub mod test_utils;

use anyhow::Context as AnyhowContext;
// use axum::Json;
use hyper::body::Bytes;
// use hyper::{Request, Response};
use log::{error, info};
use nix::libc::{ioctl, TIOCSCTTY};
use nix::unistd::{dup2, setsid};
use openpty::openpty;
use russh::keys::{PrivateKey, PublicKey, PublicKeyBase64};
use russh::server::Server;
use russh::{server, ChannelId, MethodKind};
use serde::Serialize;
use ssh_key;
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
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::{mpsc, Mutex};
// use tokio_stream::StreamExt;
use tracing::{debug, instrument, trace};

// use pmond::ProcMon;
use ws::WSServer;

// File paths for SSH authentication
pub mod auth;
pub mod handlers;
pub mod utils;

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
    active_handlers: Arc<std::sync::Mutex<HashMap<usize, Arc<tokio::sync::Mutex<SshHandler>>>>>,
    /// Track connected clients with their remote forward listeners
    pub connected_clients: Arc<tokio::sync::Mutex<HashMap<usize, ConnectedClientInfo>>>,
}

/// Information about a connected client
#[derive(Clone, Debug, Serialize)]
pub struct ConnectedClientInfo {
    pub id: usize,
    pub user: String,
    pub comment: String,
    pub options: Option<String>,
    pub remote_forward_listeners: Vec<(String, u32)>,
    pub connected_at: SystemTime,
}

#[derive(Clone)]
pub struct AppState {
    pub ssh_server: Arc<SshServer>,
    //pub proc_mon: Arc<ProcMon>,
    pub ws_server: Arc<WSServer>,
    pub target_http_address: Option<String>,
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
            None => crate::auth::load_or_generate_key(&base_dir),
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
            base_dir,
            active_handlers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            connected_clients: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    pub fn get_config(&self) -> server::Config {
        let mut config = server::Config::default();
        config.keys.push(self.keys.clone());
        config.max_auth_attempts = 3;
        config.server_id = russh::SshId::Standard(String::from("SSH-2.0-Rust-SSH-Server"));
        config
    }
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
    comment: String,
    options: Option<String>,
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
                info!("Validating certificate for user: {}", user);
                crate::auth::validate_certificate(&key_openssh, &user_str, &ca_keys).await
            } else {
                info!("Validating public key for user: {}", user);
                crate::auth::validate_public_key(&user_str, &key_openssh, &authorized_keys).await
            };

            if let Ok(ref auth_res) = auth_result {
                if let server::Auth::Accept = auth_res.status {
                    let mut clients = connected_clients.lock().await;
                    let client_info = ConnectedClientInfo {
                        id: handler_id,
                        user: user_str.clone(),
                        comment: auth_res.comment.clone(),
                        options: auth_res.options.clone(),
                        remote_forward_listeners: Vec::new(),
                        connected_at: SystemTime::now(),
                    };
                    clients.insert(handler_id, client_info);
                }
            }

            auth_result.map(|r| r.status)
        }
    }

    /// This is called when a new stream (called channel) is opened on a client connection
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
                    let (tcp_reader, tcp_writer) = tcp_stream.into_split();
                    let channel_id = channel_id;

                    // Store the TCP writer for SSH to TCP forwarding
                    let tcp_writers = self.tcp_writers.clone();
                    let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                    {
                        let mut writers = tcp_writers.lock().await;
                        writers.insert(channel_id, tx);
                    }

                    // Spawn task to forward data from TCP -> SSH channel
                    let session_handle_clone = session_handle.clone();
                    let tcp_writers_clone = tcp_writers.clone();
                    tokio::spawn(async move {
                        crate::utils::pipe_read_to_ssh(
                            tcp_reader,
                            session_handle_clone,
                            channel_id,
                            "TCP to SSH",
                        )
                        .await;
                        let mut writers = tcp_writers_clone.lock().await;
                        writers.remove(&channel_id);
                    });

                    // Spawn task to forward data from SSH channel -> TCP connection
                    let tcp_writers_clone2 = tcp_writers.clone();
                    tokio::spawn(async move {
                        crate::utils::pipe_rx_to_write(rx, tcp_writer, "SSH to TCP").await;
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

                let master_read = tokio::fs::File::from_std(master_read_file);
                let master_write = tokio::fs::File::from_std(master_write_file);
                drop(slave);

                // Get a handle to the SSH channel for sending data back.
                let session_handle = _session.handle();
                let ch_id = channel_id;
                // Spawn task that reads from PTY and writes to the SSH client.
                tokio::spawn(async move {
                    crate::utils::pipe_read_to_ssh(
                        master_read,
                        session_handle,
                        ch_id,
                        "PTY to SSH",
                    )
                    .await;
                });

                // Now forward data from SSH client -> PTY. Store writer in the tcp_writers map so that data() can use it.
                let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                {
                    let mut writers = tcp_writers.lock().await;
                    writers.insert(ch_id, tx);
                }
                // Spawn a task that consumes data from the channel (via the writer) and writes to the PTY master.
                let tcp_writers_clone = tcp_writers.clone();
                tokio::spawn(async move {
                    crate::utils::pipe_rx_to_write(rx, master_write, "SSH to PTY").await;
                    let mut writers = tcp_writers_clone.lock().await;
                    writers.remove(&ch_id);
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
                                        let (tcp_reader, tcp_writer) = tcp_stream.into_split();

                                        // Store the TCP writer for SSH to TCP forwarding
                                        let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                                        {
                                            let mut writers = tcp_writers_clone.lock().await;
                                            writers.insert(channel_id, tx);
                                        }

                                        // Spawn task to forward data from TCP -> SSH channel
                                        let session_handle_clone2 = session_handle_clone.clone();
                                        let tcp_writers_clone2 = tcp_writers_clone.clone();
                                        tokio::spawn(async move {
                                            crate::utils::pipe_read_to_ssh(tcp_reader, session_handle_clone2, channel_id, "TCP forwarder to SSH").await;
                                            let mut writers = tcp_writers_clone2.lock().await;
                                            writers.remove(&channel_id);
                                        });

                                        // Spawn task to forward data from SSH channel -> TCP connection
                                        let tcp_writers_clone3 = tcp_writers_clone.clone();
                                        tokio::spawn(async move {
                                            crate::utils::pipe_rx_to_write(rx, tcp_writer, "SSH to TCP forwarder").await;
                                            let mut writers = tcp_writers_clone3.lock().await;
                                            writers.remove(&channel_id);
                                        });
                                    });
                                }
                                Err(e) => error!("Failed to accept connection: {}", e),
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            info!("Shutting down remote forward listener on {}:{}", bind_addr, bind_port);
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
                let stdin = child.stdin.take().unwrap();
                let stdout = child.stdout.take().unwrap();
                let stderr = child.stderr.take().unwrap();

                // Forward SFTP stdout -> SSH data
                let session_handle_clone = session_handle.clone();
                tokio::spawn(async move {
                    crate::utils::pipe_read_to_ssh(
                        stdout,
                        session_handle_clone,
                        channel_id,
                        "SFTP stdout to SSH",
                    )
                    .await;
                });

                // Forward SFTP stderr -> SSH extended data
                let session_handle_clone2 = session_handle.clone();
                tokio::spawn(async move {
                    crate::utils::pipe_read_to_ssh_extended(
                        stderr,
                        session_handle_clone2,
                        channel_id,
                        1,
                        "SFTP stderr to SSH",
                    )
                    .await;
                });

                // Forward SSH data -> SFTP stdin
                let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                {
                    let mut writers = tcp_writers.lock().await;
                    writers.insert(channel_id, tx);
                }

                let tcp_writers_clone = tcp_writers.clone();
                tokio::spawn(async move {
                    crate::utils::pipe_rx_to_write(rx, stdin, "SSH to SFTP stdin").await;
                    let mut writers = tcp_writers_clone.lock().await;
                    writers.remove(&channel_id);
                });

                // Monitor child process exit
                let session_handle_clone3 = session_handle.clone();
                let tcp_writers_clone2 = tcp_writers.clone();
                tokio::spawn(async move {
                    debug!("SFTP process monitor task started");
                    match child.wait().await {
                        Ok(status) => {
                            debug!("SFTP server exited with status: {}", status);
                            let exit_code = status.code().unwrap_or(0) as u32;
                            let _ = session_handle_clone3
                                .exit_status_request(channel_id, exit_code)
                                .await;
                        }
                        Err(e) => {
                            error!("Error waiting for SFTP server: {}", e);
                        }
                    }
                    let _ = session_handle_clone3.close(channel_id).await;

                    // Ensure cleanup
                    let mut writers = tcp_writers_clone2.lock().await;
                    writers.remove(&channel_id);
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
            comment: String::new(),
            options: None,
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

const DEBUG_PTY: bool = false;

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
        use nix::unistd::{setuid, Uid};
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
        let server = SshServer::new(42, Some(key), base_dir);
        let config = server.get_config();

        // Verify some configuration settings
        assert_eq!(config.keys.len(), 1);
        match &config.server_id {
            russh::SshId::Standard(id) => assert_eq!(id, "SSH-2.0-Rust-SSH-Server"),
            _ => panic!("Unexpected server ID format"),
        }
    }

    #[test]
    fn test_load_or_generate_key_persistence() {
        let temp_dir = tempfile::Builder::new()
            .prefix("ssh_key_persistence_test")
            .tempdir()
            .expect("Failed to create temp dir");
        let base_dir = temp_dir.path().to_path_buf();

        // Should use auth::load_or_generate_key
        let first_key = crate::auth::load_or_generate_key(&base_dir);
        assert!(base_dir.join("meshkey.pem").exists());

        let second_key = crate::auth::load_or_generate_key(&base_dir);
        assert_eq!(
            first_key.to_bytes().unwrap(),
            second_key.to_bytes().unwrap()
        );
    }
}
