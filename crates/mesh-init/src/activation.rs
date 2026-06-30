//! Socket activation for mesh-init services.
//!
//! Handles listening on TCP ports and UDS sockets on behalf of services.
//! Supports three activation models:
//!
//! - **Systemd socket activation** — mesh-init receives pre-bound file
//!   descriptors from systemd via `LISTEN_PID`/`LISTEN_FDS`. Uses them
//!   directly instead of binding new sockets.
//! - **Listener activation (Accept=false)** - passes listening file descriptors
//!   to the child service using systemd fd 3.. + `LISTEN_FDS=N`.
//! - **Inetd-style (Accept=true)** - accepts the connection in mesh-init
//!   and passes the connected client socket as stdin/stdout/stderr.
//! - **Hybrid activation (service activation_mode=hybrid)** - accepts the
//!   connection in mesh-init and forwards the accepted fd to a service JSONL
//!   Unix socket using SCM_RIGHTS.

use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;

use parking_lot::Mutex;
use tokio::io::unix::AsyncFd;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::config::{AppConfig, ServiceActivationMode};
use crate::daemon::Daemon;
use crate::process::ActivationFd;
use crate::protocol::ServiceState;

// ============================================================================
// Concurrency limits
// ============================================================================

/// Default maximum number of concurrent inetd-style activation
/// children. Prevents a connection flood from exhausting PIDs/memory/FDs.
/// Override via the `MESH_INIT_MAX_ACTIVATION_CHILDREN` env var.
const DEFAULT_MAX_ACTIVATION_CHILDREN: usize = 64;

fn max_activation_children() -> usize {
    std::env::var("MESH_INIT_MAX_ACTIVATION_CHILDREN")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or(DEFAULT_MAX_ACTIVATION_CHILDREN)
}

/// Global semaphore capping concurrent inetd-style activation spawns.
static ACTIVATION_SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();
static SERVICE_LISTENER_FDS: OnceLock<Mutex<HashMap<String, Vec<(usize, OwnedFd)>>>> =
    OnceLock::new();

fn activation_semaphore() -> Arc<Semaphore> {
    ACTIVATION_SEMAPHORE
        .get_or_init(|| Arc::new(Semaphore::new(max_activation_children())))
        .clone()
}

fn register_service_listener_fd(service_name: &str, order: usize, fd: &OwnedFd) {
    let Ok(fd_clone) = fd.try_clone() else {
        warn!(
            "Failed to clone activation listener fd for '{}'",
            service_name
        );
        return;
    };
    let registry = SERVICE_LISTENER_FDS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry.lock();
    let listeners = registry.entry(service_name.to_string()).or_default();
    if let Some((_, existing)) = listeners.iter_mut().find(|(idx, _)| *idx == order) {
        *existing = fd_clone;
    } else {
        listeners.push((order, fd_clone));
        listeners.sort_by_key(|(idx, _)| *idx);
    }
}

fn service_listener_fds(service_name: &str) -> Vec<OwnedFd> {
    let Some(registry) = SERVICE_LISTENER_FDS.get() else {
        return Vec::new();
    };
    registry
        .lock()
        .get(service_name)
        .map(|listeners| {
            listeners
                .iter()
                .filter_map(|(_, fd)| fd.try_clone().ok())
                .collect()
        })
        .unwrap_or_default()
}

// ============================================================================
// Systemd socket activation — FD identification
// ============================================================================

/// The kind of a systemd socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketKind {
    Stream,
    Datagram,
}

/// Identity of a systemd socket activation file descriptor.
#[derive(Debug, Clone, PartialEq)]
enum FdIdentity {
    Tcp(u16, SocketKind),
    Unix(PathBuf, SocketKind),
    Unknown,
}

/// Global pool of file descriptors received from systemd socket activation.
/// Populated once by [`collect_systemd_fds`] before any listener starts.
static SYSTEMD_FDS: OnceLock<Mutex<VecDeque<(OwnedFd, FdIdentity)>>> = OnceLock::new();

/// Collect file descriptors from systemd socket activation.
///
/// Checks `LISTEN_PID` and `LISTEN_FDS` environment variables. If the PID
/// matches the current process and `LISTEN_FDS > 0`, takes ownership of the
/// file descriptors starting from FD 3 and populates the global [`SYSTEMD_FDS`]
/// pool. Clears both environment variables so they are not inherited by child
/// processes.
///
/// Must be called early in startup, before any activation listeners are started.
/// Idempotent — only the first call has effect.
pub fn collect_systemd_fds() {
    if SYSTEMD_FDS.get().is_some() {
        return;
    }

    let listen_pid = match std::env::var("LISTEN_PID") {
        Ok(pid_str) => match pid_str.parse::<u32>() {
            Ok(pid) if pid == std::process::id() => pid,
            _ => return,
        },
        Err(_) => return,
    };

    let listen_fds: usize = match std::env::var("LISTEN_FDS") {
        Ok(fds_str) => match fds_str.parse() {
            Ok(n) if n > 0 => n,
            _ => return,
        },
        Err(_) => return,
    };

    // Clear env vars so children don't misinterpret them as their own activation
    // SAFETY: removing these env vars is safe — they were set by systemd and
    // are only meaningful for the process that matches LISTEN_PID (us).
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
    }

    info!(
        "Detected systemd socket activation: LISTEN_PID={}, LISTEN_FDS={}",
        listen_pid, listen_fds,
    );

    const SD_LISTEN_FDS_START: i32 = 3;
    let pool = SYSTEMD_FDS.get_or_init(|| Mutex::new(VecDeque::new()));
    let mut pool = pool.lock();

    for i in 0..listen_fds {
        let raw_fd = SD_LISTEN_FDS_START + i as i32;
        // SAFETY: systemd guarantees these FDs are open and their ownership
        // is transferred to us when `LISTEN_PID` matches our PID.
        let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let identity = identify_fd(&owned);
        debug!(
            "Systemd activation FD {} (raw_fd={}): {:?}",
            i, raw_fd, identity
        );
        pool.push_back((owned, identity));
    }

    info!(
        "Collected {} systemd activation file descriptor(s)",
        listen_fds
    );
}

/// Identify the type, address, and socket kind of a file descriptor.
fn identify_fd(fd: &OwnedFd) -> FdIdentity {
    let raw_fd = fd.as_raw_fd();

    // Determine socket type (SOCK_STREAM vs SOCK_DGRAM)
    let sock_kind = get_sock_type(raw_fd);

    // Try UDS first
    let mut sockaddr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(
            raw_fd,
            &mut sockaddr as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    if ret == 0 && sockaddr.sun_family == libc::AF_UNIX as libc::sa_family_t {
        use std::os::unix::ffi::OsStrExt;
        let path_bytes: &[i8] = &sockaddr.sun_path;
        let path_len = path_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_bytes.len());
        if path_len > 0 && path_bytes[0] != 0 {
            // SAFETY: casting i8 sun_path to u8 for OsStrExt::from_bytes.
            // The path bytes are valid ASCII/UTF-8 filesystem paths.
            let bytes: &[u8] =
                unsafe { std::slice::from_raw_parts(path_bytes.as_ptr() as *const u8, path_len) };
            let path = PathBuf::from(<std::ffi::OsStr as OsStrExt>::from_bytes(bytes));
            return FdIdentity::Unix(path, sock_kind);
        }
        // Abstract namespace or empty — treat as Unknown
        return FdIdentity::Unknown;
    }

    // Try TCP (IPv4)
    let mut sockaddr_in: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(
            raw_fd,
            &mut sockaddr_in as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    if ret == 0 && sockaddr_in.sin_family == libc::AF_INET as libc::sa_family_t {
        let port = u16::from_be(sockaddr_in.sin_port);
        return FdIdentity::Tcp(port, sock_kind);
    }

    // Try TCP (IPv6)
    let mut sockaddr_in6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(
            raw_fd,
            &mut sockaddr_in6 as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    if ret == 0 && sockaddr_in6.sin6_family == libc::AF_INET6 as libc::sa_family_t {
        let port = u16::from_be(sockaddr_in6.sin6_port);
        return FdIdentity::Tcp(port, sock_kind);
    }

    FdIdentity::Unknown
}

/// Determine the socket type (SOCK_STREAM or SOCK_DGRAM) via `getsockopt(SO_TYPE)`.
fn get_sock_type(raw_fd: i32) -> SocketKind {
    let mut sock_type: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut sock_type as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 && sock_type == libc::SOCK_DGRAM {
        SocketKind::Datagram
    } else {
        SocketKind::Stream
    }
}

/// Try to take a matching systemd-provided TCP listener FD by port and kind.
fn take_systemd_tcp_fd(port: u16, datagram: bool) -> Option<OwnedFd> {
    let kind = if datagram {
        SocketKind::Datagram
    } else {
        SocketKind::Stream
    };
    let pool = SYSTEMD_FDS.get()?;
    let mut pool = pool.lock();
    let idx = pool.iter().position(
        |(_, identity)| matches!(identity, FdIdentity::Tcp(p, k) if *p == port && *k == kind),
    );
    idx.map(|i| pool.remove(i).unwrap().0)
}

/// Try to take a matching systemd-provided UDS listener FD by path and kind.
fn take_systemd_uds_fd(path: &str, datagram: bool) -> Option<OwnedFd> {
    let kind = if datagram {
        SocketKind::Datagram
    } else {
        SocketKind::Stream
    };
    let pool = SYSTEMD_FDS.get()?;
    let mut pool = pool.lock();
    let idx = pool.iter().position(|(_, identity)| {
        if let FdIdentity::Unix(p, k) = identity {
            p.as_os_str() == path && *k == kind
        } else {
            false
        }
    });
    idx.map(|i| pool.remove(i).unwrap().0)
}

// ============================================================================
// Peer credential helper
// ============================================================================

/// Get peer UID from a raw file descriptor using SO_PEERCRED.
fn get_peer_uid(fd: i32) -> Option<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 {
        Some(cred.uid)
    } else {
        warn!("Failed to get peer credentials for fd {}", fd);
        None
    }
}

async fn forward_accepted_fd(
    service_name: &str,
    activation_socket: &str,
    client_fd: OwnedFd,
    stream_cache: &mut Option<StdUnixStream>,
    daemon: Arc<Daemon>,
) -> anyhow::Result<()> {
    let message = serde_json::json!({
        "method": "accepted_fd",
        "service": service_name,
        "activation_socket": activation_socket,
        "peer_uid": get_peer_uid(client_fd.as_raw_fd()),
    });

    if stream_cache.is_none() {
        *stream_cache = Some(
            connect_or_start_activation_socket(service_name, activation_socket, daemon.clone())
                .await?,
        );
    }

    if let Some(stream) = stream_cache.as_mut() {
        if mesh::jsonl::send_json_with_fd(stream, &message, &client_fd).is_ok() {
            return Ok(());
        }
    }

    debug!(
        "Activation fd send to {} for '{}' failed; reconnecting",
        activation_socket, service_name
    );
    *stream_cache = None;
    let mut stream =
        connect_or_start_activation_socket(service_name, activation_socket, daemon).await?;
    mesh::jsonl::send_json_with_fd(&mut stream, &message, &client_fd)?;
    *stream_cache = Some(stream);
    Ok(())
}

async fn connect_or_start_activation_socket(
    service_name: &str,
    activation_socket: &str,
    daemon: Arc<Daemon>,
) -> anyhow::Result<StdUnixStream> {
    match StdUnixStream::connect(activation_socket) {
        Ok(stream) => Ok(stream),
        Err(first_error) => {
            debug!(
                "Activation socket {} for '{}' not ready: {}",
                activation_socket, service_name, first_error
            );
            start_activation_socket_target(service_name, activation_socket, daemon)?;
            connect_activation_socket(activation_socket).await
        }
    }
}

fn start_activation_socket_target(
    service_name: &str,
    activation_socket: &str,
    daemon: Arc<Daemon>,
) -> anyhow::Result<()> {
    let already_running = {
        let services = daemon.services.lock();
        services
            .get(service_name)
            .is_some_and(|p| p.state == ServiceState::Running || p.state == ServiceState::Starting)
    };

    if already_running {
        return Ok(());
    }

    let mut config = daemon
        .configs
        .lock()
        .get(service_name)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing service config for {}", service_name))?;

    if let Some(context) = daemon.take_activation_context(service_name) {
        config.env.extend(context.to_env());
    }

    let listener = bind_activation_socket(activation_socket)?;
    daemon
        .start_service_with_config(config, Some(ActivationFd::Listen(vec![listener])))
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("failed to start forward target {}: {}", service_name, e))
}

fn bind_activation_socket(path: &str) -> anyhow::Result<OwnedFd> {
    let path_ref = std::path::Path::new(path);
    if let Some(parent) = path_ref.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(path_ref);

    let listener = std::os::unix::net::UnixListener::bind(path_ref)?;
    listener.set_nonblocking(true)?;

    if let Ok(metadata) = std::fs::metadata(path_ref) {
        let mut perms = metadata.permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o660);
        let _ = std::fs::set_permissions(path_ref, perms);
    }

    Ok(listener.into())
}

fn activation_socket_for_service(config: &AppConfig, service_name: &str) -> String {
    config
        .activation_socket
        .clone()
        .unwrap_or_else(|| default_activation_socket(service_name))
}

fn default_activation_socket(service_name: &str) -> String {
    mesh::paths::AppPaths::for_app(service_name)
        .control_socket(service_name)
        .to_string_lossy()
        .into_owned()
}

async fn connect_activation_socket(path: &str) -> anyhow::Result<StdUnixStream> {
    let mut last_error = None;
    for _ in 0..40 {
        match StdUnixStream::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last_error = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }

    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("failed to connect to {}", path)))
}

// ============================================================================
// Start listeners
// ============================================================================

/// Start activation listeners for a given service.
pub fn start_listeners(daemon: Arc<Daemon>, config: &AppConfig) {
    for (order, act) in config.activation.iter().enumerate() {
        if let Some(port) = act.port {
            // Check for pre-bound systemd socket activation FD
            if let Some(fd) = take_systemd_tcp_fd(port, act.datagram) {
                info!(
                    "Using systemd socket FD for '{}' TCP port {} (datagram={})",
                    config.name, port, act.datagram
                );
                let daemon_clone = daemon.clone();
                let name = config.name.clone();
                let wait = act.wait;
                if wait {
                    register_service_listener_fd(&name, order, &fd);
                }
                tokio::spawn(async move {
                    handle_listener(fd, name, wait, daemon_clone).await;
                });
                continue;
            }
            let daemon_clone = daemon.clone();
            let name = config.name.clone();
            let wait = act.wait;
            tokio::spawn(async move {
                run_tcp_listener(port, name, wait, order, daemon_clone).await;
            });
        }
        if let Some(ref path) = act.socket {
            // Check for pre-bound systemd socket activation FD
            if let Some(fd) = take_systemd_uds_fd(path, act.datagram) {
                info!("Using systemd socket FD for '{}' UDS {}", config.name, path);
                let daemon_clone = daemon.clone();
                let name = config.name.clone();
                let wait = act.wait;
                if wait {
                    register_service_listener_fd(&name, order, &fd);
                }
                tokio::spawn(async move {
                    handle_listener(fd, name, wait, daemon_clone).await;
                });
                continue;
            }
            let daemon_clone = daemon.clone();
            let name = config.name.clone();
            let path_clone = path.clone();
            let wait = act.wait;
            let socket_mode = act.socket_mode;
            let socket_user = act.socket_user.clone();
            let socket_group = act.socket_group.clone();
            tokio::spawn(async move {
                run_uds_listener(
                    path_clone,
                    name,
                    wait,
                    order,
                    socket_mode,
                    socket_user,
                    socket_group,
                    daemon_clone,
                )
                .await;
            });
        }
    }
}

// ============================================================================
// TCP listener
// ============================================================================

async fn run_tcp_listener(
    port: u16,
    service_name: String,
    wait: bool,
    order: usize,
    daemon: Arc<Daemon>,
) {
    let bind_addr = daemon
        .configs
        .lock()
        .get(&service_name)
        .and_then(|c| {
            c.activation
                .iter()
                .find_map(|a| a.bind.clone().filter(|b| !b.is_empty()))
        })
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let addr = format!("{}:{}", bind_addr, port);
    if bind_addr == "0.0.0.0" || bind_addr == "::" {
        warn!(
            "TCP activation for '{}' binds {} — ensure auth or firewalling is in place",
            service_name, addr
        );
    }
    info!(
        "Starting TCP activation listener for '{}' on {} (wait={})",
        service_name, addr, wait
    );

    if wait {
        let has_auth = daemon
            .configs
            .lock()
            .get(&service_name)
            .is_some_and(|c| c.auth.is_some());
        if has_auth {
            error!(
                "Service '{}' has auth configured but uses listener activation, \
                 which cannot enforce peer authentication. Refusing to start the \
                 listener. Remove the auth config or use Accept=true.",
                service_name
            );
            return;
        }
    }

    let listener = match std::net::TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            error!(
                "Failed to bind TCP activation port {} for '{}': {}",
                port, service_name, e
            );
            return;
        }
    };
    if let Err(e) = listener.set_nonblocking(true) {
        error!("Failed to set TCP listener non-blocking: {}", e);
        return;
    }

    let fd = listener.into();
    if wait {
        register_service_listener_fd(&service_name, order, &fd);
    }
    handle_listener(fd, service_name, wait, daemon).await;
}

// ============================================================================
// UDS listener
// ============================================================================

async fn run_uds_listener(
    path: String,
    service_name: String,
    wait: bool,
    order: usize,
    socket_mode: Option<u32>,
    socket_user: Option<String>,
    socket_group: Option<String>,
    daemon: Arc<Daemon>,
) {
    info!(
        "Starting UDS activation listener for '{}' on {}",
        service_name, path
    );
    if let Some(parent) = std::path::Path::new(&path).parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        error!(
            "Failed to create UDS activation socket directory {} for '{}': {}",
            parent.display(),
            service_name,
            e
        );
        return;
    }
    let _ = std::fs::remove_file(&path);

    let listener = match std::os::unix::net::UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            error!(
                "Failed to bind UDS activation socket {} for '{}': {}",
                path, service_name, e
            );
            return;
        }
    };

    // Apply socket permissions from config, or default 0o660
    if let Ok(metadata) = std::fs::metadata(&path) {
        let mode = socket_mode.unwrap_or(0o660);
        let mut perms = metadata.permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, mode);
        let _ = std::fs::set_permissions(&path, perms);
    }

    // Apply socket ownership from config
    if let Some(user) = socket_user {
        if unsafe { libc::getuid() } == 0 {
            let uid = match user.parse::<u32>() {
                Ok(n) => n,
                Err(_) => {
                    // Resolve username to UID
                    let c_user = std::ffi::CString::new(user.as_str()).unwrap_or_default();
                    let pw = unsafe { libc::getpwnam(c_user.as_ptr()) };
                    if pw.is_null() {
                        warn!(
                            "Failed to resolve socket user '{}' for '{}'",
                            user, service_name
                        );
                        0
                    } else {
                        unsafe { (*pw).pw_uid }
                    }
                }
            };
            let c_path = std::ffi::CString::new(path.as_str()).unwrap_or_default();
            let gid = socket_group
                .as_ref()
                .and_then(|g| {
                    if g.is_empty() {
                        None
                    } else {
                        match g.parse::<u32>() {
                            Ok(n) => Some(n),
                            Err(_) => {
                                let c_group =
                                    std::ffi::CString::new(g.as_str()).unwrap_or_default();
                                let gr = unsafe { libc::getgrnam(c_group.as_ptr()) };
                                if gr.is_null() {
                                    warn!(
                                        "Failed to resolve socket group '{}' for '{}'",
                                        g, service_name
                                    );
                                    None
                                } else {
                                    Some(unsafe { (*gr).gr_gid })
                                }
                            }
                        }
                    }
                })
                .unwrap_or(u32::MAX);
            unsafe {
                libc::chown(c_path.as_ptr() as *const _, uid, gid);
            }
        } else {
            warn!("Not running as root, cannot chown UDS socket '{}'", path);
        }
    } else if let Some(group) = socket_group
        && unsafe { libc::getuid() } == 0
    {
        let gid = match group.parse::<u32>() {
            Ok(n) => n,
            Err(_) => {
                let c_group = std::ffi::CString::new(group.as_str()).unwrap_or_default();
                let gr = unsafe { libc::getgrnam(c_group.as_ptr()) };
                if gr.is_null() {
                    warn!(
                        "Failed to resolve socket group '{}' for '{}'",
                        group, service_name
                    );
                    u32::MAX
                } else {
                    unsafe { (*gr).gr_gid }
                }
            }
        };
        let c_path = std::ffi::CString::new(path.as_str()).unwrap_or_default();
        unsafe {
            libc::chown(c_path.as_ptr() as *const _, u32::MAX, gid);
        }
    }

    if let Err(e) = listener.set_nonblocking(true) {
        error!("Failed to set UDS listener non-blocking: {}", e);
        return;
    }

    let fd = listener.into();
    if wait {
        register_service_listener_fd(&service_name, order, &fd);
    }
    handle_listener(fd, service_name, wait, daemon).await;
}

// ============================================================================
// Core listener loop
// ============================================================================

async fn handle_listener(
    listener_fd: OwnedFd,
    service_name: String,
    wait: bool,
    daemon: Arc<Daemon>,
) {
    let async_fd = match AsyncFd::new(listener_fd) {
        Ok(afd) => afd,
        Err(e) => {
            error!("Failed to register listener FD with tokio: {}", e);
            return;
        }
    };
    let mut activation_stream: Option<StdUnixStream> = None;

    loop {
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(e) => {
                error!("Listener wait error for {}: {}", service_name, e);
                break;
            }
        };

        debug!("Activation connection ready for {}", service_name);

        if wait {
            // Accept=false: pass the listening FD to the child using systemd-style activation.
            let already_running = {
                let services = daemon.services.lock();
                services.get(&service_name).is_some_and(|p| {
                    p.state == ServiceState::Running || p.state == ServiceState::Starting
                })
            };
            if already_running {
                guard.clear_ready();
                continue;
            }

            let config_opt = daemon.configs.lock().get(&service_name).cloned();
            if let Some(mut config) = config_opt {
                if config.auth.is_some() {
                    warn!(
                        "Auth configuration is ignored for listener activation on service '{}'",
                        service_name
                    );
                }

                if let Some(context) = daemon.take_activation_context(&service_name) {
                    config.env.extend(context.to_env());
                }

                let mut fds = service_listener_fds(&service_name);
                if fds.is_empty()
                    && let Ok(fd) = async_fd.get_ref().try_clone()
                {
                    fds.push(fd);
                }
                let passed_fd = Some(ActivationFd::Listen(fds));
                if let Err(e) = daemon.start_service_with_config(config, passed_fd) {
                    error!("Failed to activate service {}: {}", service_name, e);
                }
            }

            guard.clear_ready();
        } else {
            // Accept=true: accept and pass the client fd in inetd style.
            let raw_fd = async_fd.get_ref().as_raw_fd();
            let client_fd =
                unsafe { libc::accept(raw_fd, std::ptr::null_mut(), std::ptr::null_mut()) };

            if client_fd < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                error!("Accept error on {}: {}", service_name, err);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }

            guard.retain_ready();
            let client_owned = unsafe { OwnedFd::from_raw_fd(client_fd) };

            let config_opt = daemon.configs.lock().get(&service_name).cloned();
            if let Some(mut config) = config_opt {
                if let Some(context) = daemon.take_activation_context(&service_name) {
                    config.env.extend(context.to_env());
                }

                // UDS peer auth check
                if let Some(ref auth) = config.auth {
                    let peer_uid = get_peer_uid(client_owned.as_raw_fd());
                    let current_uid = unsafe { libc::getuid() };

                    if let Some(peer_uid) = peer_uid {
                        if !auth.is_uid_authorized(peer_uid, current_uid) {
                            error!(
                                "Rejected activation for '{}' from unauthorized UID {}",
                                service_name, peer_uid
                            );
                            drop(client_owned);
                            continue;
                        }

                        if let Some(_pattern) = auth.get_delegate(peer_uid) {
                            config
                                .env
                                .insert("X_PEER_DELEGATE_UID".to_string(), peer_uid.to_string());
                        } else {
                            config
                                .env
                                .insert("X_PEER_UID".to_string(), peer_uid.to_string());
                        }
                    } else {
                        error!(
                            "Rejected activation for '{}': auth configured but peer UID unavailable (TCP?)",
                            service_name
                        );
                        drop(client_owned);
                        continue;
                    }
                }

                if config.activation_mode == ServiceActivationMode::Hybrid {
                    let activation_socket = activation_socket_for_service(&config, &service_name);
                    if let Err(e) = forward_accepted_fd(
                        &service_name,
                        &activation_socket,
                        client_owned,
                        &mut activation_stream,
                        daemon.clone(),
                    )
                    .await
                    {
                        error!(
                            "Failed to forward activated fd for {} to {}: {}",
                            service_name, activation_socket, e
                        );
                    }
                    continue;
                }

                let cg = crate::cgroup::create_cgroup(&service_name)
                    .unwrap_or_else(|_| "/sys/fs/cgroup".to_string());

                let permit = match activation_semaphore().acquire_owned().await {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Activation semaphore closed for '{}': {}", service_name, e);
                        drop(client_owned);
                        continue;
                    }
                };

                match crate::process::spawn_process(
                    &config,
                    &cg,
                    Some(ActivationFd::Stdio(client_owned)),
                ) {
                    Ok(pid) => {
                        debug!("Spawned activated instance PID {}", pid);
                        tokio::spawn(async move {
                            let _permit = permit;
                            loop {
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                if unsafe { libc::kill(pid as i32, 0) } != 0 {
                                    break;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!(
                            "Failed to spawn activated instance for {}: {}",
                            service_name, e
                        );
                        drop(permit);
                    }
                }
            }
        }
    }
}
