//! Socket activation for mesh-init services.
//!
//! Handles listening on TCP ports, UDP ports, and Unix sockets on behalf of services.
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

use std::collections::{HashMap, HashSet, VecDeque};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;

use parking_lot::Mutex;
use tokio::io::unix::AsyncFd;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::config::{ActivationConfig, AppConfig, ServiceActivationMode};
use crate::daemon::{Daemon, apply_activation_context_env};
use crate::process::{ActivationFd, ActivationListenFd};
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
static SERVICE_LISTENER_FDS: OnceLock<
    Mutex<HashMap<String, Vec<(usize, OwnedFd, Option<String>)>>>,
> = OnceLock::new();
static ACTIVE_INETD_PERMITS: OnceLock<Mutex<HashMap<u32, tokio::sync::OwnedSemaphorePermit>>> =
    OnceLock::new();

pub fn register_inetd_permit(pid: u32, permit: tokio::sync::OwnedSemaphorePermit) {
    let registry = ACTIVE_INETD_PERMITS.get_or_init(|| Mutex::new(HashMap::new()));
    registry.lock().insert(pid, permit);
}

pub fn reclaim_inetd_permit(pid: u32) {
    if let Some(registry) = ACTIVE_INETD_PERMITS.get() {
        if registry.lock().remove(&pid).is_some() {
            debug!(pid, "inetd_permit_reclaimed");
        }
    }
}

fn activation_semaphore() -> Arc<Semaphore> {
    ACTIVATION_SEMAPHORE
        .get_or_init(|| Arc::new(Semaphore::new(max_activation_children())))
        .clone()
}

/// Register one listener for a service in the daemon-held registry.
///
/// Listeners arrive from activations and from FDSTORE notifications; both
/// feed warm restarts and the LISTEN_FDS hand-off.
pub(crate) fn register_service_listener_fd(
    service_name: &str,
    order: usize,
    fd: &OwnedFd,
    fd_name: Option<String>,
) {
    let Ok(fd_clone) = fd.try_clone() else {
        warn!(service = %service_name, "clone_activation_listener_fd_failed");
        return;
    };
    let registry = SERVICE_LISTENER_FDS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry.lock();
    let listeners = registry.entry(service_name.to_string()).or_default();
    if let Some((_, existing, existing_name)) =
        listeners.iter_mut().find(|(idx, _, _)| *idx == order)
    {
        *existing = fd_clone;
        *existing_name = fd_name;
    } else {
        listeners.push((order, fd_clone, fd_name));
        listeners.sort_by_key(|(idx, _, _)| *idx);
    }
}

/// Release all stored listener FDs when a configured service is removed.
pub(crate) fn discard_service_listener_fds(service: &str) {
    if let Some(registry) = SERVICE_LISTENER_FDS.get() {
        registry.lock().remove(service);
    }
}

pub(crate) fn service_listener_fds(service_name: &str) -> Vec<ActivationListenFd> {
    let Some(registry) = SERVICE_LISTENER_FDS.get() else {
        return Vec::new();
    };
    registry
        .lock()
        .get(service_name)
        .map(|listeners| {
            listeners
                .iter()
                .filter_map(|(_, fd, name)| {
                    fd.try_clone().ok().map(|fd| ActivationListenFd {
                        fd,
                        name: name.clone(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Edge-free readability check for a listener socket.
///
/// Tokio's `AsyncFd` is edge-triggered, so a connection that was already
/// queued before a freeze produced no fresh readiness event. After each
/// freeze, run one `poll(fd, 0)` pass over the listeners; any connection
/// already pending thaws the service at once.
pub(crate) fn has_pending_connection(fd: i32) -> bool {
    let mut pollfd = [libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    // Non-blocking read check: timeout 0 returns immediately.
    let rc = unsafe { libc::poll(pollfd.as_mut_ptr(), 1, 0) };
    if rc <= 0 {
        return false;
    }
    let revents = pollfd[0].revents;
    revents & (libc::POLLIN | libc::POLLRDNORM | libc::POLLRDHUP) != 0
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
static SYSTEMD_FDS: OnceLock<Mutex<VecDeque<(OwnedFd, FdIdentity, Option<String>)>>> =
    OnceLock::new();

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
    let listen_fd_names: Vec<Option<String>> = std::env::var("LISTEN_FDNAMES")
        .ok()
        .map(|names| {
            names
                .split(|c: char| c == ':' || c.is_ascii_whitespace())
                .filter(|name| !name.is_empty())
                .map(|name| {
                    if name.is_empty() {
                        None
                    } else {
                        Some(name.to_string())
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    // Clear env vars so children don't misinterpret them as their own activation
    // SAFETY: removing these env vars is safe — they were set by systemd and
    // are only meaningful for the process that matches LISTEN_PID (us).
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
    }

    info!(listen_pid, listen_fds, "systemd_socket_activation_detected");

    const SD_LISTEN_FDS_START: i32 = 3;
    let pool = SYSTEMD_FDS.get_or_init(|| Mutex::new(VecDeque::new()));
    let mut pool = pool.lock();

    for i in 0..listen_fds {
        let raw_fd = SD_LISTEN_FDS_START + i as i32;
        // SAFETY: systemd guarantees these FDs are open and their ownership
        // is transferred to us when `LISTEN_PID` matches our PID.
        let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let identity = identify_fd(&owned);
        let fd_name = listen_fd_names.get(i).cloned().flatten();
        debug!(
            index = i,
            raw_fd,
            identity = ?identity,
            name = ?fd_name,
            "systemd_activation_fd_processed"
        );
        pool.push_back((owned, identity, fd_name));
    }

    info!(count = listen_fds, "systemd_fds_collected");
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
fn take_systemd_tcp_fd(port: u16, datagram: bool) -> Option<ActivationListenFd> {
    let kind = if datagram {
        SocketKind::Datagram
    } else {
        SocketKind::Stream
    };
    let pool = SYSTEMD_FDS.get()?;
    let mut pool = pool.lock();
    let idx = pool.iter().position(
        |(_, identity, _)| matches!(identity, FdIdentity::Tcp(p, k) if *p == port && *k == kind),
    );
    idx.map(|i| {
        let (fd, _, name) = pool.remove(i).unwrap();
        ActivationListenFd { fd, name }
    })
}

/// Try to take a matching systemd-provided UDS listener FD by path and kind.
fn take_systemd_uds_fd(path: &str, datagram: bool) -> Option<ActivationListenFd> {
    let kind = if datagram {
        SocketKind::Datagram
    } else {
        SocketKind::Stream
    };
    let pool = SYSTEMD_FDS.get()?;
    let mut pool = pool.lock();
    let idx = pool.iter().position(|(_, identity, _)| {
        if let FdIdentity::Unix(p, k) = identity {
            p.as_os_str() == path && *k == kind
        } else {
            false
        }
    });
    idx.map(|i| {
        let (fd, _, name) = pool.remove(i).unwrap();
        ActivationListenFd { fd, name }
    })
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
        warn!(fd, "get_peer_credentials_failed");
        None
    }
}

/// Resolve a username to a UID via the reentrant libc lookup.
///
/// Returns `None` on missing user, NUL byte in the name, or lookup error.
/// Uses `getpwnam_r` so concurrent calls from async tasks don't race on
/// libc's static passwd buffer.
fn lookup_uid_by_name(name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16 * 1024];
    let rc = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(entry.pw_uid)
}

/// Resolve a group name to a GID via the reentrant libc lookup.
fn lookup_gid_by_name(name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16 * 1024];
    let rc = unsafe {
        libc::getgrnam_r(
            c_name.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(entry.gr_gid)
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
        socket = %activation_socket,
        service = %service_name,
        "activation_fd_send_failed_reconnecting"
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
                socket = %activation_socket,
                service = %service_name,
                error = %first_error,
                "activation_socket_not_ready_starting_target"
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
        services.get(service_name).is_some_and(|p| {
            matches!(
                p.protocol_state(),
                ServiceState::Running | ServiceState::Starting
            )
        })
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

    let context = daemon.take_activation_context(service_name);
    apply_activation_context_env(&mut config, context);

    let listener = bind_activation_socket(activation_socket)?;
    daemon
        .start_service_with_config(
            config,
            Some(ActivationFd::Listen(vec![ActivationListenFd {
                fd: listener,
                name: Some("activation".to_string()),
            }])),
        )
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

/// Bound sockets survive handler replacement, so reload can move a socket to a
/// different service without rebinding it or losing queued connections.
#[derive(Default)]
pub(crate) struct ListenerSet {
    listeners: Vec<ManagedListener>,
}

struct ManagedListener {
    owner: String,
    order: usize,
    config: ActivationConfig,
    fd: OwnedFd,
    fd_name: Option<String>,
    task: Option<tokio::task::JoinHandle<()>>,
    path_identity: Option<(u64, u64)>,
}

fn same_socket(a: &ActivationConfig, b: &ActivationConfig) -> bool {
    fn bind(act: &ActivationConfig) -> &str {
        act.bind
            .as_deref()
            .filter(|b| !b.is_empty())
            .unwrap_or("::")
            .trim_start_matches('[')
            .trim_end_matches(']')
    }
    a.port == b.port
        && a.socket == b.socket
        && a.vsock_port == b.vsock_port
        && a.vsock_cid == b.vsock_cid
        && a.datagram == b.datagram
        && bind(a) == bind(b)
}

impl ManagedListener {
    async fn pause(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }

    fn remove_path(&self) {
        if let (Some(path), Some(identity)) = (&self.config.socket, self.path_identity) {
            if std::fs::symlink_metadata(path)
                .ok()
                .is_some_and(|m| (m.dev(), m.ino()) == identity)
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

impl ListenerSet {
    /// Pause activation while a service's process/configuration is replaced.
    pub(crate) async fn pause(&mut self, names: &[String]) {
        for listener in &mut self.listeners {
            if names.contains(&listener.owner) {
                listener.pause().await;
            }
        }
    }

    /// Reconcile configured sockets, retaining bound FDs across ownership,
    /// name and order changes. Binding errors are returned for the reload reply.
    pub(crate) async fn reconcile(
        &mut self,
        daemon: Arc<Daemon>,
        configs: &[AppConfig],
    ) -> Vec<String> {
        let mut old = std::mem::take(&mut self.listeners);
        let previous_keys: Vec<_> = old.iter().map(|l| (l.owner.clone(), l.order)).collect();
        let mut affected = HashSet::new();
        for listener in &old {
            if !configs.iter().any(|cfg| {
                cfg.name == listener.owner
                    && cfg.activation.get(listener.order) == Some(&listener.config)
            }) {
                affected.insert(listener.owner.clone());
            }
        }
        for cfg in configs {
            if cfg.activation.iter().enumerate().any(|(order, act)| {
                !old.iter()
                    .any(|l| l.owner == cfg.name && l.order == order && l.config == *act)
            }) {
                affected.insert(cfg.name.clone());
            }
        }
        // Pause every sibling of a changed listener before editing that
        // service's registry. Untouched services keep their complete FD set.
        for listener in &mut old {
            if affected.contains(&listener.owner) {
                listener.pause().await;
            }
        }
        // Retire addresses absent from the new snapshot before binding any
        // additions (a replacement bind may overlap an old wildcard address).
        let mut retained = Vec::new();
        for mut listener in old {
            if configs.iter().any(|cfg| {
                cfg.name != "default"
                    && cfg
                        .activation
                        .iter()
                        .any(|act| same_socket(&listener.config, act))
            }) {
                retained.push(listener);
            } else {
                listener.pause().await;
                // Release the configured registry clone too, before an
                // overlapping replacement address is bound.
                if let Some(registry) = SERVICE_LISTENER_FDS.get() {
                    if let Some(fds) = registry.lock().get_mut(&listener.owner) {
                        fds.retain(|(order, _, _)| *order != listener.order);
                    }
                }
                listener.remove_path();
            }
        }
        let mut old = retained;
        let mut errors = Vec::new();
        let mut failed = HashSet::new();
        for config in configs.iter().filter(|c| c.name != "default") {
            for (order, act) in config.activation.iter().enumerate() {
                if self.listeners.iter().any(|l| same_socket(&l.config, act)) {
                    failed.insert(config.name.clone());
                    errors.push(format!("{}: duplicate activation socket", config.name));
                    continue;
                }
                if (act.datagram && !act.wait) || (act.wait && config.auth.is_some()) {
                    failed.insert(config.name.clone());
                    errors.push(format!(
                        "{}: unsupported activation/auth combination",
                        config.name
                    ));
                    continue;
                }
                let previous = old.iter().position(|l| same_socket(&l.config, act));
                let mut listener = if let Some(index) = previous {
                    let mut listener = old.remove(index);
                    if listener.owner != config.name
                        || listener.config != *act
                        || listener.order != order
                    {
                        listener.pause().await;
                    }
                    if listener.owner != config.name || listener.config.fd_name != act.fd_name {
                        listener.fd_name = act.fd_name.clone();
                    }
                    listener.owner = config.name.clone();
                    listener.order = order;
                    listener.config = act.clone();
                    if let Some(path) = &act.socket {
                        apply_uds_permissions(path, act, &config.name);
                    }
                    listener
                } else {
                    match bind_activation_listener(act, &config.name) {
                        Ok((fd, fd_name)) => ManagedListener {
                            owner: config.name.clone(),
                            order,
                            config: act.clone(),
                            fd,
                            fd_name,
                            task: None,
                            path_identity: act.socket.as_ref().and_then(|path| {
                                std::fs::symlink_metadata(path)
                                    .ok()
                                    .map(|m| (m.dev(), m.ino()))
                            }),
                        },
                        Err(e) => {
                            error!(service = %config.name, error = %e, "bind_activation_socket_failed");
                            failed.insert(config.name.clone());
                            errors.push(format!("{}: {:?}: {}", config.name, act, e));
                            continue;
                        }
                    }
                };
                if listener
                    .task
                    .as_ref()
                    .is_some_and(|task| task.is_finished())
                {
                    listener.pause().await;
                }
                self.listeners.push(listener);
            }
        }
        for mut listener in old {
            listener.pause().await;
            listener.remove_path();
        }
        let mut registrations = Vec::new();
        let mut handlers = Vec::new();
        for (index, listener) in self.listeners.iter().enumerate() {
            if listener.config.wait {
                match listener.fd.try_clone() {
                    Ok(fd) => registrations.push((
                        listener.owner.clone(),
                        listener.order,
                        fd,
                        listener.fd_name.clone(),
                    )),
                    Err(e) => {
                        failed.insert(listener.owner.clone());
                        errors.push(format!("{}: clone listener: {}", listener.owner, e));
                    }
                }
            }
            if listener.task.is_none() {
                match listener.fd.try_clone() {
                    Ok(fd) => handlers.push((index, fd)),
                    Err(e) => {
                        failed.insert(listener.owner.clone());
                        errors.push(format!("{}: clone handler: {}", listener.owner, e));
                    }
                }
            }
        }
        for listener in &mut self.listeners {
            if failed.contains(&listener.owner) {
                listener.pause().await;
            }
        }
        // Replace configured registrations in one critical section. An
        // untouched handler on another worker must never observe a partial set.
        let registry = SERVICE_LISTENER_FDS.get_or_init(|| Mutex::new(HashMap::new()));
        {
            let mut registry = registry.lock();
            for (name, order) in previous_keys {
                if let Some(fds) = registry.get_mut(&name) {
                    fds.retain(|(index, _, _)| *index != order);
                }
            }
            for (name, order, fd, fd_name) in registrations {
                let fds = registry.entry(name).or_default();
                fds.retain(|(index, _, _)| *index != order);
                fds.push((order, fd, fd_name));
                fds.sort_by_key(|(index, _, _)| *index);
            }
            registry.retain(|_, fds| !fds.is_empty());
        }
        // A queued request may activate only after its complete listener set
        // has bound successfully. A later reload retries failed services.
        for (index, fd) in handlers {
            let listener = &mut self.listeners[index];
            if !failed.contains(&listener.owner) {
                let name = listener.owner.clone();
                let wait = listener.config.wait;
                let daemon = daemon.clone();
                listener.task = Some(tokio::spawn(async move {
                    handle_listener(fd, name, wait, daemon).await;
                }));
            }
        }
        errors
    }
}

fn bind_activation_listener(
    act: &ActivationConfig,
    service: &str,
) -> std::io::Result<(OwnedFd, Option<String>)> {
    if let Some(port) = act.port {
        if let Some(fd) = take_systemd_tcp_fd(port, act.datagram) {
            return Ok((fd.fd, fd.name));
        }
        let bind = act
            .bind
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("[::]");
        return bind_inet_socket(bind, port, act.datagram).map(|fd| (fd, act.fd_name.clone()));
    }
    if let Some(path) = &act.socket {
        if let Some(fd) = take_systemd_uds_fd(path, act.datagram) {
            return Ok((fd.fd, fd.name));
        }
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(path);
        let fd = bind_unix_socket(path, act.datagram)?;
        apply_uds_permissions(path, act, service);
        return Ok((fd, act.fd_name.clone()));
    }
    if let Some(port) = act.vsock_port {
        if !act.datagram {
            return bind_vsock_listener(act.vsock_cid.unwrap_or(VMADDR_CID_ANY), port)
                .map(|fd| (fd, act.fd_name.clone()));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "unsupported activation socket",
    ))
}

fn bind_inet_socket(bind_addr: &str, port: u16, datagram: bool) -> std::io::Result<OwnedFd> {
    if datagram {
        let socket = bind_udp_socket(bind_addr, port)?;
        return Ok(unsafe { OwnedFd::from_raw_fd(socket.into_raw_fd()) });
    }

    let listener = bind_tcp_listener(bind_addr, port)?;
    listener.set_nonblocking(true)?;
    Ok(listener.into())
}

fn bind_tcp_listener(bind_addr: &str, port: u16) -> std::io::Result<std::net::TcpListener> {
    let host = bind_addr
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(bind_addr);

    if host.contains(':')
        && let Ok(ip) = host
            .split_once('%')
            .map(|(addr, _)| addr)
            .unwrap_or(host)
            .parse::<std::net::Ipv6Addr>()
    {
        return bind_ipv6_dual_stack(ip, port);
    }

    std::net::TcpListener::bind(format!("{}:{}", bind_addr, port))
}

fn bind_udp_socket(bind_addr: &str, port: u16) -> std::io::Result<std::net::UdpSocket> {
    let host = bind_addr
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(bind_addr);
    let bind_target = if host.contains(':') && !bind_addr.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", bind_addr, port)
    };
    let socket = std::net::UdpSocket::bind(bind_target)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn bind_ipv6_dual_stack(
    ip: std::net::Ipv6Addr,
    port: u16,
) -> std::io::Result<std::net::TcpListener> {
    use std::os::fd::FromRawFd;

    // SAFETY: libc::socket returns a new fd or -1.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let close_fd = |fd| {
        // SAFETY: fd is owned by this function until converted with from_raw_fd.
        let _ = unsafe { libc::close(fd) };
    };

    let reuse: libc::c_int = 1;
    // SAFETY: setsockopt reads `reuse` for the specified size.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&reuse as *const libc::c_int).cast(),
            std::mem::size_of_val(&reuse) as libc::socklen_t,
        )
    } != 0
    {
        let err = std::io::Error::last_os_error();
        close_fd(fd);
        return Err(err);
    }

    let v6only: libc::c_int = 0;
    // SAFETY: setsockopt reads `v6only` for the specified size.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            (&v6only as *const libc::c_int).cast(),
            std::mem::size_of_val(&v6only) as libc::socklen_t,
        )
    } != 0
    {
        let err = std::io::Error::last_os_error();
        close_fd(fd);
        return Err(err);
    }

    let octets = ip.octets();
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: octets },
        sin6_scope_id: 0,
    };
    // SAFETY: addr points to a valid sockaddr_in6 for the specified length.
    if unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_in6).cast(),
            std::mem::size_of_val(&addr) as libc::socklen_t,
        )
    } != 0
    {
        let err = std::io::Error::last_os_error();
        close_fd(fd);
        return Err(err);
    }
    // SAFETY: fd is a valid socket fd.
    if unsafe { libc::listen(fd, 128) } != 0 {
        let err = std::io::Error::last_os_error();
        close_fd(fd);
        return Err(err);
    }

    // SAFETY: fd is uniquely owned and is now transferred to TcpListener.
    Ok(unsafe { std::net::TcpListener::from_raw_fd(fd) })
}

// ============================================================================
// AF_VSOCK listener
// ============================================================================

#[cfg(target_os = "linux")]
const VMADDR_CID_ANY: u32 = 0xffff_ffff;

#[cfg(not(target_os = "linux"))]
const VMADDR_CID_ANY: u32 = 0xffff_ffff;

#[cfg(target_os = "linux")]
fn bind_vsock_listener(cid: u32, port: u32) -> std::io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_fd_nonblocking(fd.as_raw_fd())?;

    let addr = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: cid,
        svm_zero: [0; 4],
    };
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::listen(fd.as_raw_fd(), 128) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

#[cfg(not(target_os = "linux"))]
fn bind_vsock_listener(_cid: u32, _port: u32) -> std::io::Result<OwnedFd> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "AF_VSOCK is only supported on Linux",
    ))
}

fn set_fd_nonblocking(fd: i32) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ============================================================================
// UDS listener
// ============================================================================

fn apply_uds_permissions(path: &str, act: &ActivationConfig, service: &str) {
    // Apply socket permissions from config, or default to public local IPC.
    // Apps authenticate requests at the protocol layer.
    if let Ok(metadata) = std::fs::metadata(&path) {
        let mode = act.socket_mode.unwrap_or(0o666);
        let mut perms = metadata.permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, mode);
        let _ = std::fs::set_permissions(&path, perms);
    }

    // Apply socket ownership from config
    if let Some(user) = &act.socket_user {
        if unsafe { libc::getuid() } == 0 {
            let uid = match user.parse::<u32>() {
                Ok(n) => n,
                Err(_) => match lookup_uid_by_name(&user) {
                    Some(n) => n,
                    None => {
                        // Don't fall back to UID 0 (root) — that would
                        // chown the socket to root. Leave ownership unchanged.
                        warn!(
                            user = %user,
                            service = %service,
                            "resolve_socket_user_failed"
                        );
                        u32::MAX
                    }
                },
            };
            let c_path = std::ffi::CString::new(path).unwrap_or_default();
            let gid = act
                .socket_group
                .as_ref()
                .and_then(|g| {
                    if g.is_empty() {
                        None
                    } else {
                        Some(match g.parse::<u32>() {
                            Ok(n) => n,
                            Err(_) => match lookup_gid_by_name(g) {
                                Some(n) => n,
                                None => {
                                    warn!(
                                        group = %g,
                                        service = %service,
                                        "resolve_socket_group_failed"
                                    );
                                    u32::MAX
                                }
                            },
                        })
                    }
                })
                .unwrap_or(u32::MAX);
            unsafe {
                libc::chown(c_path.as_ptr() as *const _, uid, gid);
            }
        } else {
            warn!(path = %path, "cannot_chown_non_root");
        }
    } else if let Some(group) = &act.socket_group
        && unsafe { libc::getuid() } == 0
    {
        let gid = match group.parse::<u32>() {
            Ok(n) => n,
            Err(_) => match lookup_gid_by_name(&group) {
                Some(n) => n,
                None => {
                    warn!(
                        group = %group,
                        service = %service,
                        "resolve_socket_group_failed"
                    );
                    u32::MAX
                }
            },
        };
        let c_path = std::ffi::CString::new(path).unwrap_or_default();
        unsafe {
            libc::chown(c_path.as_ptr() as *const _, u32::MAX, gid);
        }
    }
}

fn bind_unix_socket(path: &str, datagram: bool) -> std::io::Result<OwnedFd> {
    if datagram {
        let socket = std::os::unix::net::UnixDatagram::bind(path)?;
        socket.set_nonblocking(true)?;
        return Ok(socket.into());
    }

    let listener = std::os::unix::net::UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    Ok(listener.into())
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
            error!(error = %e, "register_listener_fd_failed");
            return;
        }
    };
    let mut activation_stream: Option<StdUnixStream> = None;

    loop {
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(e) => {
                error!(service = %service_name, error = %e, "listener_wait_error");
                break;
            }
        };

        debug!(service = %service_name, "activation_connection_ready");

        if wait {
            // Accept=false: pass the listening FD to the child using systemd-style activation.
            // Phase 1: a Frozen or Freezing service is woken, not started a second time.
            let state_probe = {
                let services = daemon.services.lock();
                services.get(&service_name).map(|p| p.state)
            };
            if let Some(state) = state_probe {
                match state {
                    crate::states::ServiceState::Frozen { .. }
                    | crate::states::ServiceState::Freezing { .. } => {
                        // One poll(fd, 0) sweep first: an already-queued
                        // connection must thaw the service right away.
                        let has_queued = has_pending_connection(async_fd.get_ref().as_raw_fd());
                        info!(
                            service = %service_name,
                            queued = has_queued,
                            "activation_wake_thaw_service"
                        );
                        if let Err(error) = daemon.ensure_running(&service_name, None, None).await {
                            error!(service = %service_name, error = %error, "wake_service_failed");
                        }
                        guard.clear_ready();
                        continue;
                    }
                    crate::states::ServiceState::Stopped => {}
                    // Starting/Running/Stopping: already tracked by the daemon.
                    _ => {
                        guard.clear_ready();
                        continue;
                    }
                }
            }

            let already_running = {
                let services = daemon.services.lock();
                services.get(&service_name).is_some_and(|p| {
                    matches!(
                        p.protocol_state(),
                        ServiceState::Running | ServiceState::Starting
                    )
                })
            };
            if already_running {
                guard.clear_ready();
                continue;
            }

            let config_opt = daemon.configs.lock().get(&service_name).cloned();
            if let Some(mut config) = config_opt {
                if config.auth.is_some() {
                    warn!(service = %service_name, "auth_ignored_for_listener_activation");
                }

                let context = daemon.take_activation_context(&service_name);
                apply_activation_context_env(&mut config, context);

                let mut fds = service_listener_fds(&service_name);
                if fds.is_empty()
                    && let Ok(fd) = async_fd.get_ref().try_clone()
                {
                    fds.push(ActivationListenFd { fd, name: None });
                }
                let passed_fd = Some(ActivationFd::Listen(fds));
                if let Err(e) = daemon
                    .ensure_running(&service_name, Some(config), passed_fd)
                    .await
                {
                    error!(service = %service_name, error = %e, "activate_service_failed");
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
                error!(service = %service_name, error = %err, "accept_failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }

            guard.retain_ready();
            let client_owned = unsafe { OwnedFd::from_raw_fd(client_fd) };

            let config_opt = daemon.configs.lock().get(&service_name).cloned();
            if let Some(mut config) = config_opt {
                let context = daemon.take_activation_context(&service_name);
                apply_activation_context_env(&mut config, context);

                // UDS peer auth check
                if let Some(ref auth) = config.auth {
                    let peer_uid = get_peer_uid(client_owned.as_raw_fd());
                    let current_uid = unsafe { libc::getuid() };

                    if let Some(peer_uid) = peer_uid {
                        if !auth.is_uid_authorized(peer_uid, current_uid) {
                            error!(
                                service = %service_name,
                                peer_uid,
                                "activation_rejected_unauthorized_uid"
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
                            service = %service_name,
                            "activation_rejected_peer_uid_unavailable"
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
                            service = %service_name,
                            socket = %activation_socket,
                            error = %e,
                            "forward_activated_fd_failed"
                        );
                    }
                    continue;
                }

                let cg = crate::cgroup::create_cgroup(&service_name)
                    .unwrap_or_else(|_| "/sys/fs/cgroup".to_string());

                let permit = match activation_semaphore().acquire_owned().await {
                    Ok(p) => p,
                    Err(e) => {
                        error!(service = %service_name, error = %e, "activation_semaphore_closed");
                        drop(client_owned);
                        continue;
                    }
                };

                match crate::process::spawn_process(
                    &config,
                    &cg,
                    Some(ActivationFd::Stdio(client_owned)),
                ) {
                    Ok((pid, _)) => {
                        debug!(pid, "spawned_activated_instance");
                        if let Some(ref tracked) = *daemon.tracked_child_pids.lock() {
                            tracked.lock().insert(pid);
                        }
                        register_inetd_permit(pid, permit);
                    }
                    Err(e) => {
                        error!(
                            service = %service_name,
                            error = %e,
                            "spawn_activated_instance_failed"
                        );
                        drop(permit);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_udp_socket_returns_datagram_fd() {
        let fd = bind_inet_socket("127.0.0.1", 0, true).unwrap();
        assert_eq!(get_sock_type(fd.as_raw_fd()), SocketKind::Datagram);
    }

    #[test]
    fn bind_unix_datagram_socket_returns_datagram_fd() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("svc.sock");
        let fd = bind_unix_socket(path.to_str().unwrap(), true).unwrap();
        assert_eq!(get_sock_type(fd.as_raw_fd()), SocketKind::Datagram);
        assert!(path.exists());
    }
}
