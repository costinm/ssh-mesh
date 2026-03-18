use log::{error, info};
use tracing::{debug, instrument, trace};

use nix::libc::{TIOCSCTTY, ioctl};
use nix::unistd::{dup2, setsid};

use openpty::openpty;

use russh::keys::{HashAlg, PublicKey, PublicKeyBase64};
use russh::{ChannelId, MethodKind, server};

use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::process::Stdio;
use std::sync::Arc;
use std::time::SystemTime;

use hyper::body::Bytes;
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::{Mutex, mpsc};

use crate::{ConnectedClientInfo, MeshNode};

/// SshHandler is responsible for one server multiplexed connection.
///
/// Connections may use TCP - or H2 tunnel, websockets, virtio.
#[allow(unused)]
#[derive(Clone)]
pub struct SshHandler {
    pub(crate) id: usize,
    pub(crate) server: MeshNode,

    // streams multiplexed on the client TCP connection
    // TODO: rename to streams, including (exec/shell) session and forwards.
    sessions: Arc<Mutex<HashMap<ChannelId, ChannelSession>>>,

    /// Channel writers, handling incoming data from client for opened
    /// channels.
    channel_writers: Arc<Mutex<HashMap<ChannelId, mpsc::UnboundedSender<Bytes>>>>,

    // Listeners for remote forwarding ((address, port) -> shutdown_sender)
    remote_forward_listeners: Arc<Mutex<HashMap<(String, u32), mpsc::UnboundedSender<()>>>>,

    user: String,

    comment: String,
    options: Option<String>,
}

const DEBUG_PTY: bool = false;

#[derive(Debug, Clone)]
struct PtyInfo {
    col_width: u32,
    row_height: u32,
    pix_width: u32,
    pix_height: u32,
}

/// Exec/Shell stream, with optional PTY support,
struct ChannelSession {
    pty: Option<PtyInfo>,
    shell: bool,
    env: HashMap<String, String>,
    // Process handling for PTY/shell sessions
    process: Option<tokio::process::Child>,
    pty_master: Option<std::fs::File>,
}

/// Build a `Command` for the given program and arguments.
/// For shell_request: program="/bin/sh", args=[].
/// For exec_request: if command starts with "/" use it directly, otherwise use "sh -c <cmd>".
fn build_command(command: &Option<String>) -> Command {
    match command.as_deref() {
        None => {
            // shell_request: interactive shell
            Command::new("/bin/sh")
        }
        Some(cmd) if cmd.starts_with('/') => {
            // exec_request with absolute path: run directly
            Command::new(cmd)
        }
        Some(cmd) => {
            // exec_request with relative command: wrap in sh -c
            let mut c = Command::new("sh");
            c.arg("-c").arg(cmd);
            c
        }
    }
}

impl SshHandler {
    pub(crate) fn new(id: usize, server: MeshNode) -> Self {
        SshHandler {
            id,
            server,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            channel_writers: Arc::new(Mutex::new(HashMap::new())),
            remote_forward_listeners: Arc::new(Mutex::new(HashMap::new())),
            user: String::new(),
            comment: String::new(),
            options: None,
        }
    }

    /// Shared implementation for both exec_request and shell_request.
    ///
    /// When `command` is None, spawns an interactive shell (/bin/sh).
    /// When `command` is Some, executes the given command (directly if it
    /// starts with "/", otherwise via "sh -c").
    ///
    /// If the user previously requested a PTY for this channel, the process
    /// is attached to a PTY and I/O is streamed through it. Otherwise, the
    /// process uses pipes for stdin/stdout/stderr with stdout and stderr
    /// forwarded independently.
    fn spawn_command(
        command: Option<String>,
        channel_id: ChannelId,
        sessions: Arc<Mutex<HashMap<ChannelId, ChannelSession>>>,
        channel_writers: Arc<Mutex<HashMap<ChannelId, mpsc::UnboundedSender<Bytes>>>>,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), anyhow::Error>> + Send {
        let session_handle = session.handle();
        let mut cmd = build_command(&command);
        let label = match &command {
            None => "shell".to_string(),
            Some(c) => format!("exec({})", c),
        };

        async move {
            let mut sessions_lock = sessions.lock().await;
            let channel_session = match sessions_lock.get_mut(&channel_id) {
                Some(cs) => cs,
                None => {
                    trace!(
                        "No session found for channel {:?} when processing {} request",
                        channel_id, label
                    );
                    return Ok(());
                }
            };
            channel_session.shell = true;

            // Apply environment variables
            for (key, value) in &channel_session.env {
                cmd.env(key, value);
            }

            let has_pty = channel_session.pty.is_some();

            if has_pty {
                // ---- PTY mode ----
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

                let slave_fd = pty.1.as_raw_fd();
                let slave_file = &pty.1;

                cmd.env("TERM", "xterm-256color");
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
                        setsid().map_err(|e| std::io::Error::other(e))?;
                        if ioctl(slave_fd, TIOCSCTTY, 0) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        dup2(slave_fd, 0).map_err(|e| std::io::Error::other(e))?;
                        dup2(slave_fd, 1).map_err(|e| std::io::Error::other(e))?;
                        dup2(slave_fd, 2).map_err(|e| std::io::Error::other(e))?;
                        Ok(())
                    });
                }

                let child = cmd.spawn().map_err(|e| anyhow::anyhow!(e))?;
                channel_session.process = Some(child);

                // Set up PTY I/O forwarding
                let master = channel_session.pty_master.as_ref().unwrap();
                let master_fd = master.as_raw_fd();
                trace!("PTY created with master fd {}", master_fd);

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

                let master_read_file = unsafe { std::fs::File::from_raw_fd(master_fd_read) };
                let master_write_file = unsafe { std::fs::File::from_raw_fd(master_fd_write) };
                let master_read = tokio::fs::File::from_std(master_read_file);
                let master_write = tokio::fs::File::from_std(master_write_file);
                drop(sessions_lock);
                drop(pty.1); // drop slave

                // PTY master -> SSH channel
                let sh = session_handle.clone();
                let ch = channel_id;
                tokio::spawn(async move {
                    crate::utils::pipe_read_to_ssh(master_read, sh, ch, "PTY to SSH").await;
                });

                // SSH channel -> PTY master
                let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                {
                    let mut writers = channel_writers.lock().await;
                    writers.insert(channel_id, tx);
                }
                let tw = channel_writers.clone();
                tokio::spawn(async move {
                    crate::utils::pipe_rx_to_write(rx, master_write, "SSH to PTY").await;
                    let mut writers = tw.lock().await;
                    writers.remove(&ch);
                });
            } else {
                // ---- Pipe mode (no PTY) ----
                cmd.stdin(Stdio::piped());
                cmd.stdout(Stdio::piped());
                cmd.stderr(Stdio::piped());

                let mut child = cmd.spawn().map_err(|e| anyhow::anyhow!(e))?;

                let stdin = child.stdin.take().unwrap();
                let stdout = child.stdout.take().unwrap();
                let stderr = child.stderr.take().unwrap();

                channel_session.process = Some(child);

                drop(sessions_lock);

                // stdout -> SSH data
                let sh1 = session_handle.clone();
                let ch = channel_id;
                tokio::spawn(async move {
                    crate::utils::pipe_read_to_ssh(stdout, sh1, ch, "stdout to SSH").await;
                });

                // stderr -> SSH extended data (type 1 = stderr)
                let sh2 = session_handle.clone();
                tokio::spawn(async move {
                    crate::utils::pipe_read_to_ssh_extended(stderr, sh2, ch, 1, "stderr to SSH")
                        .await;
                });

                // SSH channel -> stdin
                let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                {
                    let mut writers = channel_writers.lock().await;
                    writers.insert(channel_id, tx);
                }
                // TODO: not sure if this is the most efficient method.
                let tw = channel_writers.clone();
                tokio::spawn(async move {
                    crate::utils::pipe_rx_to_write(rx, stdin, "SSH to stdin").await;
                    let mut writers = tw.lock().await;
                    writers.remove(&ch);
                });
            }

            // Monitor child process for exit status
            let sessions_for_exit = sessions.clone();
            let tw_exit = channel_writers.clone();
            let sh_exit = session_handle.clone();
            tokio::spawn(async move {
                // Take ownership of the child from the session
                let mut child = {
                    let mut sl = sessions_for_exit.lock().await;
                    match sl.get_mut(&channel_id) {
                        Some(cs) => match cs.process.take() {
                            Some(c) => c,
                            None => return,
                        },
                        None => return,
                    }
                };

                match child.wait().await {
                    Ok(status) => {
                        let exit_code = status.code().unwrap_or(0) as u32;
                        debug!(
                            "{} exited with status {} (code {})",
                            label, status, exit_code
                        );
                        let _ = sh_exit.exit_status_request(channel_id, exit_code).await;
                    }
                    Err(e) => {
                        error!("Error waiting for {} process: {}", label, e);
                    }
                }
                let _ = sh_exit.eof(channel_id).await;
                let _ = sh_exit.close(channel_id).await;

                // Cleanup writer
                let mut writers = tw_exit.lock().await;
                writers.remove(&channel_id);
            });

            Ok(())
        }
    }

    /// Helper to connect to a Unix Domain Socket (UDS).
    /// Handles abstract namespace if path starts with '_'.
    async fn connect_uds(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        socket_path: &str,
        session_handle: russh::server::Handle,
    ) -> Result<bool, anyhow::Error> {
        let channel_id = channel.id();
        let sessions = self.sessions.clone();
        let channel_writers = self.channel_writers.clone();
        let handler_id = self.id;
        let socket_path_str = socket_path.to_string();

        trace!(
            "Processing UDS connection for: {} (handler ID: {})",
            socket_path_str, handler_id
        );

        // Handle abstract namespace: replace leading '_' with '\0'
        let path_bytes = if socket_path_str.starts_with('_') {
            let mut bytes = Vec::with_capacity(socket_path_str.len());
            bytes.push(0);
            bytes.extend_from_slice(socket_path_str[1..].as_bytes());
            bytes
        } else {
            socket_path_str.clone().into_bytes()
        };

        // Create a new session entry for this channel
        let channel_session = ChannelSession {
            pty: None,
            shell: false,
            env: HashMap::new(),
            process: None,
            pty_master: None,
        };

        // Store the session in our sessions map
        {
            let mut sessions_lock = sessions.lock().await;
            sessions_lock.insert(channel_id, channel_session);
        }

        trace!(
            "Created new UDS session for channel {:?} in handler {}",
            channel_id, handler_id
        );

        // Establish connection to the UDS
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        use std::path::Path;

        let os_str = OsStr::from_bytes(&path_bytes);
        let path = Path::new(os_str);

        match UnixStream::connect(path).await {
            Ok(stream) => {
                trace!("Successfully connected to UDS {}", socket_path_str);

                // Set up bidirectional data forwarding
                let (uds_reader, uds_writer) = stream.into_split();

                // Store the writer for SSH to UDS forwarding
                let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                {
                    let mut writers = channel_writers.lock().await;
                    writers.insert(channel_id, tx);
                }

                // Spawn task to forward data from UDS -> SSH channel
                let session_handle_clone = session_handle.clone();
                let channel_writers_clone = channel_writers.clone();
                tokio::spawn(async move {
                    crate::utils::pipe_read_to_ssh(
                        uds_reader,
                        session_handle_clone,
                        channel_id,
                        "UDS to SSH",
                    )
                    .await;
                    let mut writers = channel_writers_clone.lock().await;
                    writers.remove(&channel_id);
                });

                // Spawn task to forward data from SSH channel -> UDS
                let channel_writers_clone2 = channel_writers.clone();
                tokio::spawn(async move {
                    crate::utils::pipe_rx_to_write(rx, uds_writer, "SSH to UDS").await;
                    let mut writers = channel_writers_clone2.lock().await;
                    writers.remove(&channel_id);
                });

                info!("UDS forwarding established for {}", socket_path_str);
                Ok(true)
            }
            Err(e) => {
                error!(
                    "Failed to connect to UDS {}: {} (handler ID: {})",
                    socket_path_str, e, handler_id
                );
                Ok(false) // Reject the channel if we can't connect
            }
        }
    }
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
        info!(
            "Password auth attempt for user: {} {}- REJECTED",
            user, self.id
        );
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
        let authorized_keys = self.server.authorized_keys.clone();
        let ca_keys = self.server.ca_keys.clone();

        let user_str = user.to_string();

        let connected_clients = self.server.connected_clients.clone();
        let handler_id = self.id;

        self.user = user_str.clone();

        let keyfp = public_key.fingerprint(HashAlg::Sha256).to_string();

        // Serialize russh key to OpenSSH format for ssh-key crate
        let key_base64 = public_key.public_key_base64();
        let algorithm = public_key.algorithm();
        let key_type_name = algorithm.as_str();

        let key_openssh = format!("{} {}", key_type_name, key_base64);

        async move {
            // Detect if this is a certificate or regular key
            let auth_result = if key_openssh.contains("-cert-v01@openssh.com") {
                info!(
                    "Certificate auth attempt for user: {} {} {}",
                    user, self.id, &key_openssh
                );

                crate::auth::validate_certificate(&key_openssh, &user_str, &ca_keys).await
            } else {
                info!(
                    "Public key auth attempt for user: {} {} {} {}",
                    user, self.id, &key_openssh, &keyfp,
                );

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
                    self.comment = auth_res.comment.clone();
                    self.options = auth_res.options.clone();
                }
            } else {
                error!("Auth failed {}", self.id)
            }

            auth_result.map(|r| r.status)
        }
    }

    /// This is called when a new stream (called channel) is opened on a client connection
    ///
    /// This is usually a shell - message followed by env, pty - and ending
    /// with the actual shell or exec command, than data and close.
    #[instrument(skip(self, _session), fields(channel_id = ?channel.id()))]
    fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
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
                channel_id, handler_id
            );
            Ok(true)
        }
    }

    /// Connection forward from client.
    ///
    /// If port is -2 (any large value will do, e.g. 0xFFFFFFFE), treat host as a UDS path.
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
            "Direct TCP/IP connection request: {}:{} from {}:{} (handler ID: {})",
            host_to_connect, port_to_connect, originator_ip_address, originator_port, self.id
        );

        // TODO: apply the rules to map host and port to 'special'
        // internal channels.

        let channel_id = channel.id();
        let sessions = self.sessions.clone();
        let handler_id = self.id;
        let host = host_to_connect.to_string();
        let port = port_to_connect;
        let originator_ip = originator_ip_address.to_string();

        let session_handle = session.handle();

        let mut me = self.clone();
        let channel = channel;

        async move {
            // UDS support: check for port -2 (0xFFFFFFFE)
            if port == 0xFFFFFFFE {
                return me.connect_uds(channel, &host, session_handle).await;
            }

            trace!(
                "Processing direct TCP/IP connection for: {}:{} from {}:{}",
                host, port, originator_ip, originator_port
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
                channel_id, handler_id
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
                    let tcp_writers = me.channel_writers.clone();
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

                    info!("Direct TCP/IP forwarding established for {}:{}", host, port);
                    Ok(true)
                }
                Err(e) => {
                    error!(
                        "Failed to connect to target {}:{}: {} (handler ID: {})",
                        host, port, e, handler_id
                    );
                    Ok(false) // Reject the channel if we can't connect
                }
            }
        }
    }

    fn channel_open_direct_streamlocal(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        socket_path: &str,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        info!(
            "Direct streamlocal connection request: {} (handler ID: {})",
            socket_path, self.id
        );
        let mut me = self.clone();
        let channel = channel;
        let socket_path = socket_path.to_string();
        let handle = session.handle();

        async move { me.connect_uds(channel, &socket_path, handle).await }
    }

    /// This is the message used by server to accept new streams on behalf of
    /// clients - not supported from clients (open_direct_tcpip does the same).
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
    fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        // Check if this is a direct TCP/IP channel and forward data to the TCP connection
        let tcp_writers = self.channel_writers.clone();
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

    /// Tcpip_forward requests that the ssh server accepts connections
    /// on an address, and forwards them to the client
    #[instrument(skip(self, session), fields(address = %address, port = %*port))]
    fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let session_handle = session.handle();
        let tcp_writers = self.channel_writers.clone();
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

            // TODO:

            let actual_port = listener.local_addr().unwrap().port();
            info!("Started listening on {}:{}", bind_addr, actual_port);

            // Channel to signal shutdown
            let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();

            {
                let mut listeners = remote_forward_listeners.lock().await;
                listeners.insert((bind_addr.clone(), bind_port), shutdown_tx);
            }

            let remote_forward_listeners_weak = Arc::downgrade(&remote_forward_listeners);

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

                                        // Store the TCP writer for SSH→TCP forwarding
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
                        else => {
                            break;
                        }
                    }
                }
                // Cleanup
                if let Some(listeners_arc) = remote_forward_listeners_weak.upgrade() {
                    let mut listeners = listeners_arc.lock().await;
                    listeners.remove(&(bind_addr, bind_port));
                }
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

    /// Close the listening port.
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

    /// Handle streamlocal-forward@openssh.com — remote UDS forwarding.
    ///
    /// The client asks us to listen on a Unix domain socket path on the
    /// server side. When a connection arrives we open a
    /// `forwarded-streamlocal@openssh.com` channel back to the client so
    /// it can pipe data to its local socket.
    #[instrument(skip(self, session), fields(socket_path = %socket_path))]
    fn streamlocal_forward(
        &mut self,
        socket_path: &str,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        info!("streamlocal_forward request for {}", socket_path);

        let session_handle = session.handle();
        let channel_writers = self.channel_writers.clone();
        let remote_forward_listeners = self.remote_forward_listeners.clone();
        let socket_path_owned = socket_path.to_string();

        async move {
            // Remove stale socket if present
            let _ = tokio::fs::remove_file(&socket_path_owned).await;

            // Ensure parent directory exists
            if let Some(parent) = std::path::Path::new(&socket_path_owned).parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }

            let listener = match UnixListener::bind(&socket_path_owned) {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind UDS {}: {}", socket_path_owned, e);
                    return Ok(false);
                }
            };

            info!("Listening on UDS {} for streamlocal forward", socket_path_owned);

            // Channel to signal shutdown
            let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();

            {
                let mut listeners = remote_forward_listeners.lock().await;
                // Use port 0 as the key component for UDS forwards
                listeners.insert((socket_path_owned.clone(), 0), shutdown_tx);
            }

            let sp = socket_path_owned.clone();
            let remote_forward_listeners_weak = Arc::downgrade(&remote_forward_listeners);

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            match accepted {
                                Ok((uds_stream, _addr)) => {
                                    info!("Accepted connection on UDS {}", sp);
                                    let session_handle_clone = session_handle.clone();
                                    let channel_writers_clone = channel_writers.clone();
                                    let sp_clone = sp.clone();

                                    tokio::spawn(async move {
                                        // Open a forwarded-streamlocal channel
                                        // back to the client
                                        let channel = match session_handle_clone
                                            .channel_open_forwarded_streamlocal(&sp_clone)
                                            .await
                                        {
                                            Ok(channel) => channel,
                                            Err(e) => {
                                                error!(
                                                    "Failed to open forwarded-streamlocal channel for {}: {}",
                                                    sp_clone, e
                                                );
                                                return;
                                            }
                                        };
                                        let channel_id = channel.id();
                                        info!(
                                            "Opened forwarded-streamlocal channel {:?} for {}",
                                            channel_id, sp_clone
                                        );

                                        // Set up bidirectional data forwarding
                                        let (uds_reader, uds_writer) = uds_stream.into_split();

                                        // Store the UDS writer for SSH→UDS forwarding
                                        let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                                        {
                                            let mut writers = channel_writers_clone.lock().await;
                                            writers.insert(channel_id, tx);
                                        }

                                        // UDS → SSH channel
                                        let session_handle_clone2 = session_handle_clone.clone();
                                        let cw2 = channel_writers_clone.clone();
                                        tokio::spawn(async move {
                                            crate::utils::pipe_read_to_ssh(
                                                uds_reader,
                                                session_handle_clone2,
                                                channel_id,
                                                "streamlocal UDS to SSH",
                                            )
                                            .await;
                                            let mut writers = cw2.lock().await;
                                            writers.remove(&channel_id);
                                        });

                                        // SSH channel → UDS
                                        let cw3 = channel_writers_clone.clone();
                                        tokio::spawn(async move {
                                            crate::utils::pipe_rx_to_write(
                                                rx,
                                                uds_writer,
                                                "SSH to streamlocal UDS",
                                            )
                                            .await;
                                            let mut writers = cw3.lock().await;
                                            writers.remove(&channel_id);
                                        });
                                    });
                                }
                                Err(e) => {
                                    error!("Failed to accept on UDS {}: {}", sp, e);
                                }
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            info!("Shutting down streamlocal forward listener on {}", sp);
                            break;
                        }
                        else => {
                            // If shutdown channel is closed (sender dropped) or
                            // both branches are unreachable, stop the loop.
                            break;
                        }
                    }
                }
                // Cleanup socket file
                let _ = tokio::fs::remove_file(&sp).await;
                // Only attempt to remove from listener map if SshHandler still exists
                if let Some(listeners_arc) = remote_forward_listeners_weak.upgrade() {
                    let mut listeners = listeners_arc.lock().await;
                    listeners.remove(&(sp, 0));
                }
            });

            Ok(true)
        }
    }

    /// Cancel a streamlocal forward — stop listening on the UDS path.
    #[instrument(skip(self, _session), fields(socket_path = %socket_path))]
    fn cancel_streamlocal_forward(
        &mut self,
        socket_path: &str,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        info!("cancel_streamlocal_forward for {}", socket_path);
        let remote_forward_listeners = self.remote_forward_listeners.clone();
        let socket_path_owned = socket_path.to_string();

        async move {
            let mut listeners = remote_forward_listeners.lock().await;
            if let Some(shutdown_tx) = listeners.remove(&(socket_path_owned.clone(), 0)) {
                let _ = shutdown_tx.send(());
                info!("Cancelled streamlocal forward for {}", socket_path_owned);
                Ok(true)
            } else {
                log::warn!(
                    "No active streamlocal forward found for {} to cancel",
                    socket_path_owned
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
        debug!("Channel EOF: stream: {:?} client: {}", channel, self.id);
        let tcp_writers = self.channel_writers.clone();
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
        debug!("Channel closed: stream {:?} client {}", channel, self.id);

        let sessions = self.sessions.clone();
        let tcp_writers = self.channel_writers.clone();
        let _connected_clients = self.server.connected_clients.clone();
        let handler_id = self.id;
        let channel_id = channel;

        async move {
            // Remove the session from our sessions map and clean up PTY process if any
            let mut sessions_lock = sessions.lock().await;
            if let Some(mut removed_session) = sessions_lock.remove(&channel_id) {
                trace!(
                    "Removed session for channel {:?} from handler {}",
                    channel_id, handler_id
                );
                // If a PTY process was spawned, kill it.
                if let Some(mut child) = removed_session.process.take() {
                    // Attempt graceful termination, then force kill if needed.
                    let _ = child.kill().await;
                }
                drop(sessions_lock);
            } else {
                info!(
                    "No session found for channel {:?} in handler {}",
                    channel_id, handler_id
                );
            }

            // Remove the writer (PTY or TCP) for this channel if it exists
            let mut writers_lock = tcp_writers.lock().await;
            if let Some(_removed_writer) = writers_lock.remove(&channel_id) {
                trace!("Removed writer for channel {:?}", channel_id);
            } else {
                trace!("No writer found for channel {:?}", channel_id);
            }

            Ok(())
        }
    }

    // ---------- Exec and FTP ----------
    // This functionality is mainly for the admin, when user as a regular
    // user.

    // TODO: change the code to allow other users (authenticated with cert)
    // to run - in isolated containers.

    /// Exec_request is the last message in a 'session', after pty is setup and
    /// env variables are sent. May have a pty (if -t is used on client).
    #[instrument(skip(self, session), fields(channel_id = ?channel, data_len = data.len()))]
    fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let command = String::from_utf8_lossy(data).to_string();
        info!("Exec request: {} {}", command, self.id);

        Self::spawn_command(
            Some(command),
            channel,
            self.sessions.clone(),
            self.channel_writers.clone(),
            session,
        )
    }

    #[instrument(skip(self, session), fields(channel_id = ?channel))]
    fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        info!("Shell request for channel {:?}", channel);
        debug!("SSH handler ID: {}", self.id);

        Self::spawn_command(
            None,
            channel,
            self.sessions.clone(),
            self.channel_writers.clone(),
            session,
        )
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
                if DEBUG_PTY {
                    trace!("Updated PTY info for channel {:?}", channel_id);
                }
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
        trace!(
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
        trace!(
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

    /// This handles the original sftp, the only subsystem in broad use.
    /// It is equivalent to a port forward or shell execution for the binary
    /// sftp, all comms are via stdin/stderr.
    #[instrument(skip(self, session), fields(channel_id = ?channel, name = %name))]
    fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let channel_id = channel;
        let subsystem_name = name.to_string();
        let tcp_writers = self.channel_writers.clone();
        let session_handle = session.handle();

        async move {
            if subsystem_name == "sftp" {
                #[cfg(feature = "sftp")]
                if self.server.cfg.sftp_server_path.is_none() {
                    info!("Starting built-in SFTP server for channel");
                    // Create input channel (SSH -> SFTP)
                    let (tx_in, rx_in) = mpsc::unbounded_channel::<Bytes>();
                    {
                        let mut writers = tcp_writers.lock().await;
                        writers.insert(channel_id, tx_in);
                    }
                    // Create output channel (SFTP -> SSH)
                    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<Bytes>();
                    // Create the stream adapter
                    let stream = crate::utils::ChannelBytesStream {
                        reader: rx_in,
                        writer: tx_out,
                        read_buf: bytes::BytesMut::new(),
                    };
                    // Spawn task to forward SFTP output to SSH channel
                    let session_handle_clone = session_handle.clone();
                    tokio::spawn(async move {
                        while let Some(data) = rx_out.recv().await {
                            if session_handle_clone
                                .data(channel_id, data.as_ref().into())
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        let _ = session_handle_clone.eof(channel_id).await;
                        let _ = session_handle_clone.close(channel_id).await;
                    });
                    // Start SFTP server
                    let sftp_root = self.server.sftp_root();
                    tokio::spawn(async move {
                        let handler = sftp_server::FileSystemHandler::new(sftp_root);
                        russh_sftp::server::run(stream, handler).await;
                    });
                    let _ = session_handle.channel_success(channel_id).await;
                    return Ok(());
                }

                {
                    let default_path = "/usr/lib/openssh/sftp-server";
                    let sftp_server_path = self
                        .server
                        .cfg
                        .sftp_server_path
                        .as_deref()
                        .unwrap_or(default_path);

                    if !std::path::Path::new(sftp_server_path).exists() {
                        error!("SFTP server binary not found at {}", sftp_server_path);
                        let _ = session_handle.channel_failure(channel_id).await;
                        return Ok(());
                    }

                    info!(
                        "Spawning SFTP server: {} in {:?}",
                        sftp_server_path,
                        self.server.base_dir()
                    );
                    let mut cmd = Command::new(sftp_server_path);
                    cmd.current_dir(&self.server.base_dir())
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
                }
            } else {
                error!("Unsupported subsystem: {}", subsystem_name);
                let _ = session_handle.channel_failure(channel_id).await;
                Ok(())
            }
        }
    }
}
