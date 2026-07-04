//! Main daemon loop for mesh-init.
//!
//! Manages service lifecycle: loads configs, starts system services,
//! handles control requests, manages signal handling and zombie reaping.

use std::collections::{HashMap, VecDeque, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use anyhow::Result;

use parking_lot::Mutex;
use tracing::{debug, error, info, trace, warn};

use crate::config::{self, AppConfig, RestartPolicy};
use crate::observer::{self, ProcessDetailedInfo, ProcessObserver};
use crate::process::{self, ManagedProcess};
use crate::protocol::{
    ActivationContext, NamespaceKind, Request, Response, ServiceState, ServiceStatus,
};
use crate::resource::ResourceManager;

// ============================================================================
// Daemon
// ============================================================================

/// Default non-root UIDs permitted to act as a different user (i.e. spawn or
/// control a process whose UID differs from the peer's).
///
/// - `1000` — the `system` service account
///
/// In addition, the configurable sshd UID (resolved via
/// `mesh::auth::trusted_sshd_uid`, env var `MESH_TRUSTED_SSHD_UID`, default
/// 103) and the ssh-mesh UID (resolved via `mesh::auth::ssh_mesh_uid`, env var
/// `MESH_SSH_MESH_UID`, default 150) are included, since both must spawn
/// shells as other users.
///
/// Root (UID 0) is always privileged. The full list can be overridden with the
/// `MESH_INIT_PRIVILEGED_UIDS` env var (comma-separated).
///
/// **Note:** UID 1000 (system) is root-equivalent for all mesh-init
/// permissions, including system-wide observer methods. The ssh-mesh UID
/// (default 150) is trusted for terminal/start operations and impersonation
/// but NOT for observer methods — see [`require_system_or_root`].
fn privileged_uids() -> Vec<u32> {
    if let Ok(v) = std::env::var("MESH_INIT_PRIVILEGED_UIDS") {
        let parsed: Vec<u32> = v
            .split(',')
            .filter_map(|s| s.trim().parse::<u32>().ok())
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    let mut uids = vec![0];
    if let Some(sys) = mesh::auth::system_uid() {
        uids.push(sys);
    }
    if let Some(sshd) = mesh::auth::trusted_sshd_uid() {
        if !uids.contains(&sshd) {
            uids.push(sshd);
        }
    }
    if let Some(mesh) = mesh::auth::ssh_mesh_uid() {
        if !uids.contains(&mesh) {
            uids.push(mesh);
        }
    }
    uids
}

/// Require that the peer is root (0) or the system UID.
///
/// Used by system-wide observer methods (`freeze_process`, `move_process`,
/// `cgroup_high`, `clear_refs`, `freeze_cgroup`) that operate on arbitrary
/// PIDs or cgroup paths. The ssh-mesh UID and the sshd UID are **not**
/// sufficient for these operations — they must use the named-service APIs
/// (`start`/`stop`/`freeze`/`unfreeze`) instead.
fn require_system_or_root(peer_uid: u32) -> Result<(), Response> {
    if mesh::auth::is_system_or_root(peer_uid) {
        Ok(())
    } else {
        Err(Response::err(format!(
            "permission denied: system-wide observer methods require root or system UID; peer UID {} is not authorized",
            peer_uid
        )))
    }
}

/// Check whether `peer_uid` is permitted to act as `target_uid`/`target_gid`.
///
/// Privileged UIDs (see [`privileged_uids`]) may target any UID. A non-
/// privileged peer may only target its own UID. Returns `Ok(())` if allowed,
/// or `Err(Response)` with a permission-denied response.
fn check_impersonation(
    peer_uid: u32,
    peer_gid: u32,
    target_uid: u32,
    target_gid: Option<u32>,
    name: &str,
) -> Result<(), Response> {
    if privileged_uids().contains(&peer_uid) {
        return Ok(());
    }
    if target_uid != peer_uid {
        return Err(Response::err(format!(
            "permission denied: peer UID {} may not operate on service '{}' (UID {})",
            peer_uid, name, target_uid
        )));
    }
    if let Some(g) = target_gid
        && g != peer_gid
    {
        return Err(Response::err(format!(
            "permission denied: peer GID {} may not operate on service '{}' (GID {})",
            peer_gid, name, g
        )));
    }
    Ok(())
}

fn preferred_shell() -> &'static str {
    if std::path::Path::new("/opt/busybox/bin/sh").is_file() {
        "/opt/busybox/bin/sh"
    } else {
        "/bin/sh"
    }
}

/// Read the running kernel version and require at least `min_major.min_minor`.
///
/// mesh-init uses `pidfd_open(2)` / `pidfd_send_signal(2)` (Linux 5.3) to
/// make PID recycling impossible. On older kernels the daemon refuses to
/// start rather than silently falling back to `kill(2)` + `waitpid(2)`,
/// which can signal a recycled PID that no longer belongs to the service.
fn check_kernel_version(min_major: u32, min_minor: u32) {
    let raw = match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(s) => s,
        Err(error) => {
            panic!(
                "mesh-init requires Linux >= {min_major}.{min_minor} for \
                 pidfd_open / pidfd_send_signal; cannot read /proc/sys/kernel/osrelease: {error}"
            );
        }
    };
    let mut parts = raw.trim().split('.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts
        .next()
        .and_then(|p| p.split_once('-').map_or(Some(p), |(n, _)| Some(n)))
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    if (major, minor) < (min_major, min_minor) {
        panic!(
            "mesh-init requires Linux >= {min_major}.{min_minor} for \
             pidfd_open / pidfd_send_signal; running kernel is {raw} (>= 5.3 required, 2019)"
        );
    }
}

/// Configuration for the daemon.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Directories to scan for system service configs.
    pub config_dirs: Vec<String>,
    /// Path for the UDS control socket.
    pub socket_path: String,
}

/// The mesh-init daemon.
///
/// Holds the registry of managed services and handles control requests.
pub struct Daemon {
    pub config: DaemonConfig,
    pub services: Arc<Mutex<HashMap<String, ManagedProcess>>>,
    /// All loaded configs, including those not yet started.
    pub configs: Arc<Mutex<HashMap<String, AppConfig>>>,
    /// Context prepared by a control request for a later socket activation.
    pub pending_activation_contexts: Arc<Mutex<HashMap<String, VecDeque<ActivationContext>>>>,
    terminal_sessions: Arc<Mutex<HashMap<String, TerminalSession>>>,
    next_terminal_id: AtomicU64,
    observer: Arc<ProcessObserver>,
    resource_manager: Option<ResourceManager>,
    /// Set of tracked child PIDs for the reaper (only used when not PID 1).
    pub tracked_child_pids: Mutex<Option<Arc<parking_lot::Mutex<std::collections::HashSet<u32>>>>>,
    pub shutdown_tx: tokio::sync::watch::Sender<bool>,
    pub service_exit_tx: tokio::sync::broadcast::Sender<String>,
}

struct TerminalSession {
    name: String,
    pid: u32,
    pty_fd: Option<OwnedFd>,
    /// pidfd for the terminal process. Used by `pidfd_send_signal(2)` to
    /// signal without PID-recycle risk. See `process::open_pidfd`.
    pidfd: Option<OwnedFd>,
}

/// Environment variables that are dangerous when set by a caller because they
/// can hijack the spawned process (library injection, shell-config, etc.).
///
/// `PATH` is also listed because a trusted peer could shadow system
/// binaries (e.g. inject a `su` in `/tmp`).
const DEFAULT_DANGEROUS_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_BIND_NOW",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_DYNAMIC_WEAK",
    "LD_HWCAP_MASK",
    "LD_KEEPDIR",
    "LD_NOEXEC",
    "LD_ORIGIN_PATH",
    "LD_POINTER_GUARD",
    "LD_PROFILE",
    "LD_SHOW_AUXV",
    "LD_USE_LOAD_BIAS",
    "BASH_ENV",
    "ENV",
    "BASH_FUNC_*",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "NODE_OPTIONS",
    "NODE_PATH",
    "RUBYOPT",
    "GEM_PATH",
    "JAVA_TOOL_OPTIONS",
    "PATH",
];

fn dangerous_env_patterns() -> Vec<String> {
    std::env::var("MESH_DANGEROUS_ENV")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_else(|| {
            DEFAULT_DANGEROUS_ENV_VARS
                .iter()
                .map(|entry| (*entry).to_string())
                .collect()
        })
}

fn env_name_matches(key: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        if let Some(prefix) = pattern.strip_suffix('*') {
            key.starts_with(prefix)
        } else {
            key == pattern
        }
    })
}

/// Strip dangerous caller-supplied environment variables unless the service
/// explicitly allowlists that name via `AllowDangerousEnv`.
pub(crate) fn scrub_dangerous_env(env: &mut HashMap<String, String>, config: &AppConfig) {
    let dangerous = dangerous_env_patterns();
    env.retain(|key, _| {
        !env_name_matches(key, &dangerous) || env_name_matches(key, &config.allow_dangerous_env)
    });
}

pub(crate) fn apply_activation_context_env(
    config: &mut AppConfig,
    context: Option<ActivationContext>,
) {
    if let Some(context) = context {
        let mut env = context.to_env();
        scrub_dangerous_env(&mut env, config);
        config.env.extend(env);
    }
}

fn run_service_commands(
    config: &AppConfig,
    commands: &[String],
    label: &str,
    timeout_secs: Option<u64>,
) -> Result<()> {
    for command in commands {
        let exit_code = process::run_service_command(config, command, timeout_secs)
            .map_err(|e| anyhow::anyhow!("{} command '{}' failed: {}", label, command, e))?;
        if exit_code != 0 {
            anyhow::bail!("{} command '{}' exited with {}", label, command, exit_code);
        }
    }
    Ok(())
}

fn should_restart_for_policy(policy: RestartPolicy, exit_code: i32) -> bool {
    match policy {
        RestartPolicy::No => false,
        RestartPolicy::Always => true,
        RestartPolicy::OnSuccess => exit_code == 0,
        RestartPolicy::OnFailure => exit_code != 0,
        RestartPolicy::OnAbnormal | RestartPolicy::OnAbort => exit_code < 0 || exit_code >= 128,
    }
}

impl Daemon {
    /// Create a new daemon instance.
    pub fn new(config: DaemonConfig) -> Arc<Self> {
        // A10: Require Linux >= 5.3 (2019) for pidfd_open / pidfd_send_signal.
        // These syscalls make PID recycling impossible, which the
        // `kill + waitpid` flow cannot guarantee. Refuse to start on
        // older kernels rather than silently fall back to the unsafe flow.
        check_kernel_version(5, 3);

        let services = Arc::new(Mutex::new(HashMap::new()));
        let resource_manager = Some(ResourceManager::new(services.clone()));
        let observer = Arc::new(ProcessObserver::new().expect("create mesh-init process observer"));
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let (service_exit_tx, _) = tokio::sync::broadcast::channel(128);

        Arc::new(Self {
            config,
            services,
            configs: Arc::new(Mutex::new(HashMap::new())),
            pending_activation_contexts: Arc::new(Mutex::new(HashMap::new())),
            terminal_sessions: Arc::new(Mutex::new(HashMap::new())),
            next_terminal_id: AtomicU64::new(1),
            observer,
            resource_manager,
            tracked_child_pids: Mutex::new(None),
            shutdown_tx,
            service_exit_tx,
        })
    }

    fn notify_service_exit(&self, name: &str) {
        let _ = self.service_exit_tx.send(name.to_string());
    }

    /// Run the daemon main loop.
    ///
    /// 1. Load system configs
    /// 2. Start resource manager
    /// 3. Auto-start system services
    /// 4. Start UDS control server
    /// 5. If PID 1, run zombie reaper
    pub async fn run(self: &Arc<Self>) -> Result<()> {
        info!("mesh-init daemon starting");

        self.start_background_tasks();

        // Start control server (blocks)
        let server =
            crate::server::ControlServer::new(self.config.socket_path.clone(), self.clone());
        server.run().await?;

        Ok(())
    }

    /// Start resource manager and background monitoring tasks.
    pub fn start_background_tasks(self: &Arc<Self>) {
        // 1. Load configs
        let dirs: Vec<&str> = self.config.config_dirs.iter().map(|s| s.as_str()).collect();
        let loaded_configs = config::load_system_configs(&dirs);
        info!("Loaded {} service config(s)", loaded_configs.len());

        {
            let mut configs = self.configs.lock();
            for cfg in &loaded_configs {
                configs.insert(cfg.name.clone(), cfg.clone());
            }
        }

        // 2. Start resource manager
        if let Some(ref rm) = self.resource_manager {
            rm.start();
        }

        self.start_process_observer();

        // 3. Auto-start system services or start activation listeners.
        // init-* services run first (sorted by priority), then the rest.
        let startup_configs: Vec<AppConfig> = self.configs.lock().values().cloned().collect();
        let mut init_configs: Vec<AppConfig> = Vec::new();
        let mut other_configs: Vec<AppConfig> = Vec::new();
        for cfg in startup_configs {
            if cfg.name == "default" {
                // default.toml only provides defaults for execution mode
                continue;
            }
            if cfg.name.starts_with("init-") {
                init_configs.push(cfg);
            } else {
                other_configs.push(cfg);
            }
        }
        init_configs.sort_by_key(|c| c.priority);
        other_configs.sort_by_key(|c| c.priority);

        for cfg in init_configs.iter().chain(other_configs.iter()) {
            if !cfg.activation.is_empty() {
                crate::activation::start_listeners(self.clone(), cfg);
            } else {
                let should_autostart = cfg
                    .service_type
                    .as_deref()
                    .map(|t| !t.trim().is_empty())
                    .unwrap_or(false);
                if should_autostart {
                    if let Err(e) = self.start_service_internal(&cfg.name) {
                        error!("Failed to auto-start service '{}': {}", cfg.name, e);
                    }
                } else {
                    debug!(
                        "Service '{}' has no activation listeners and Type is omitted; not auto-starting",
                        cfg.name
                    );
                }
            }
        }

        // 4. Spawn child process manager (zombie reaper + restarts)
        self.start_child_manager();
    }

    fn start_process_observer(&self) {
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(1024);
        match self.observer.start(true, true, Some(event_tx.clone())) {
            Ok(()) => {}
            Err(e) => {
                warn!("failed to start mesh-init process observer: {}", e);
                return;
            }
        }

        let running = self.observer.running.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = observer::proc_netlink::run_netlink_listener(event_tx, running) {
                debug!("process netlink listener stopped: {}", e);
            }
        });

        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                match event {
                    observer::MonitoringEvent::Netlink(event) => {
                        trace!(?event, "process observer netlink event");
                    }
                    observer::MonitoringEvent::Pressure(event) => {
                        trace!(
                            cgroup = %event.cgroup_path,
                            avg10 = event.pressure_data.avg10,
                            avg60 = event.pressure_data.avg60,
                            total = event.pressure_data.total,
                            "process observer pressure event"
                        );
                    }
                }
            }
        });
    }

    /// Spawn the child process manager (zombie reaper + restart loop).
    pub fn start_child_manager(self: &Arc<Self>) {
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        let tracked = process::start_child_reaper(tx);
        // Store the tracked PIDs set so spawn sites can register children when
        // the reaper is not in catch-all (PID 1) mode.
        *self.tracked_child_pids.lock() = Some(tracked);

        let daemon_clone = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tokio::select! {
                    Some((pid, exit_code)) = rx.recv() => {
                        daemon_clone.handle_child_exit(pid, exit_code);
                    }
                    _ = tick.tick() => {
                        daemon_clone.check_restarts();
                    }
                }
            }
        });
    }

    /// Handle a control protocol request.
    pub async fn handle_request(&self, request: Request, peer_uid: u32, peer_gid: u32) -> Response {
        match request {
            Request::Start {
                name,
                args,
                env,
                context,
            } => self.handle_start(&name, args, env, context, peer_uid, peer_gid),
            Request::PrepareActivation { name, context } => {
                self.prepare_activation_context(name, context)
            }
            Request::StartTerminal { .. } => {
                Response::err("start_terminal requires a passed file descriptor")
            }
            Request::RegisterNamespace { .. } => {
                Response::err("register_namespace requires a passed file descriptor")
            }
            Request::TerminalResize {
                terminal_id,
                col_width,
                row_height,
                pix_width,
                pix_height,
            } => self.handle_terminal_resize(
                &terminal_id,
                col_width,
                row_height,
                pix_width,
                pix_height,
            ),
            Request::TerminalCommand {
                terminal_id,
                command,
                data,
            } => self.handle_terminal_command(&terminal_id, &command, data),
            Request::Stop { name, signal } => {
                self.handle_stop(&name, signal, peer_uid, peer_gid).await
            }
            Request::Freeze { name } => self.handle_freeze(&name, peer_uid, peer_gid),
            Request::Unfreeze { name } => self.handle_unfreeze(&name, peer_uid, peer_gid),
            Request::Status { name } => self.handle_status(name.as_deref()),
            Request::Shutdown => self.handle_shutdown().await,
            Request::Reload => self.handle_reload(),
            Request::Processes => self.handle_observer_processes(),
            Request::Process { pid } => self.handle_observer_process(pid),
            Request::ProcessOnly { pid } => self.handle_observer_process_only(pid),
            Request::Cgroups => self.handle_observer_cgroups(),
            Request::Cgroup { path } => self.handle_observer_cgroup(&path),
            Request::Pressure => self.handle_observer_pressure(),
            Request::CgroupHigh {
                path,
                percentage,
                interval,
            } => self.handle_observer_cgroup_high(path, percentage, interval, peer_uid),
            Request::CgroupProcs { path } => self.handle_observer_cgroup_procs(&path),
            Request::MoveProcess { pid, cgroup_name } => {
                self.handle_observer_move_process(pid, cgroup_name, peer_uid)
            }
            Request::ClearRefs { pid, value } => {
                self.handle_observer_clear_refs(pid, &value, peer_uid)
            }
            Request::FreezeProcess { pid, freeze } => {
                self.handle_observer_freeze_process(pid, freeze, peer_uid)
            }
            Request::FreezeCgroup { path, freeze } => {
                self.handle_observer_freeze_cgroup(&path, freeze, peer_uid)
            }
            // Job scheduling requests are handled by the JobScheduler, not the main Daemon service manager
            Request::ScheduleJob { .. }
            | Request::CancelJob { .. }
            | Request::EnqueueWork { .. }
            | Request::ListJobs
            | Request::JobFinished { .. }
            | Request::Event { .. } => Response::err(
                "Job scheduling requests are not handled directly by the daemon socket yet.",
            ),
        }
    }

    /// Handle a control request that carries one or more Unix file descriptors.
    pub async fn handle_request_with_fds(
        &self,
        request: Request,
        fds: Vec<OwnedFd>,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Response {
        if fds.is_empty() {
            return Response::err("request is missing passed file descriptors");
        }

        match request {
            Request::StartTerminal {
                name,
                home,
                uid,
                gid,
                pty,
                env,
                context,
                command,
                ..
            } => self.handle_start_terminal(
                &name, &home, uid, gid, pty, env, context, command, fds, peer_uid, peer_gid,
            ),
            Request::RegisterNamespace {
                name,
                kind,
                target_pid,
            } => {
                if fds.len() != 1 {
                    return Response::err(format!(
                        "register_namespace expected 1 fd, got {}",
                        fds.len()
                    ));
                }
                let fd = fds.into_iter().next().expect("one fd");
                self.handle_register_namespace(&name, kind, target_pid, fd, peer_uid, peer_gid)
            }
            _ => Response::err("request does not accept passed file descriptors"),
        }
    }

    /// Handle a control request that carries one Unix file descriptor.
    pub async fn handle_request_with_fd(
        &self,
        request: Request,
        fd: OwnedFd,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Response {
        self.handle_request_with_fds(request, vec![fd], peer_uid, peer_gid)
            .await
    }

    // ========================================================================
    // Request Handlers
    // ========================================================================

    fn handle_register_namespace(
        &self,
        name: &str,
        kind: NamespaceKind,
        target_pid: Option<u32>,
        fd: OwnedFd,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Response {
        if let Err(reason) = crate::config::validate_cgroup_name(name) {
            return Response::err(format!("invalid service name: {reason}"));
        }

        let attach = {
            let mut services = self.services.lock();
            let Some(proc) = services.get_mut(name) else {
                return Response::err(format!("service '{}' not found", name));
            };
            if proc.pid.is_none() {
                return Response::err(format!("service '{}' is not running", name));
            }
            if let Err(resp) = check_impersonation(
                peer_uid,
                peer_gid,
                proc.config.uid.unwrap_or(peer_uid),
                proc.config.gid,
                name,
            ) {
                return resp;
            }

            let fd_num = fd.as_raw_fd();
            match kind {
                NamespaceKind::Net => {
                    proc.netns_fd = Some(fd);
                    proc.namespace_pid = target_pid.or(proc.namespace_pid);
                    proc.mesh_tun_attached = false;
                    info!(
                        "Registered netns fd {} for service '{}' from peer UID {}",
                        fd_num, name, peer_uid
                    );
                }
                NamespaceKind::User => {
                    proc.userns_fd = Some(fd);
                    proc.namespace_pid = target_pid.or(proc.namespace_pid);
                    proc.mesh_tun_attached = false;
                    info!(
                        "Registered userns fd {} for service '{}' from peer UID {}",
                        fd_num, name, peer_uid
                    );
                }
            }

            if proc.config.network.backend == mesh::config::NetworkBackend::MeshTun
                && proc.netns_fd.is_some()
                && !proc.mesh_tun_attached
            {
                let service_pid = proc.namespace_pid.or(proc.pid).expect("checked running");
                let userns_path = proc
                    .userns_fd
                    .as_ref()
                    .map(|_| format!("/proc/{service_pid}/ns/user"));
                Some((
                    proc.config.name.clone(),
                    proc.config.network.clone(),
                    format!("/proc/{service_pid}/ns/net"),
                    userns_path,
                ))
            } else {
                None
            }
        };

        if let Some((service_name, network, netns_path, userns_path)) = attach {
            if let Err(error) = crate::network::attach_mesh_tun(
                &service_name,
                &network,
                &netns_path,
                userns_path.as_deref(),
            ) {
                return Response::err(error.to_string());
            }
            if let Some(proc) = self.services.lock().get_mut(name) {
                proc.mesh_tun_attached = true;
            }
        }

        Response::ok_with_data(serde_json::json!({
            "name": name,
            "kind": kind,
            "registered": true
        }))
    }

    fn handle_start(
        &self,
        name: &str,
        extra_args: Vec<String>,
        mut extra_env: HashMap<String, String>,
        context: Option<ActivationContext>,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Response {
        // Reject names that could escape the config/cgroup directories.
        if let Err(reason) = crate::config::validate_cgroup_name(name) {
            return Response::err(format!("invalid service name: {reason}"));
        }
        // Authorization: a non-privileged peer may only start services whose
        // config uid matches its own. Privileged UIDs may start any service.
        {
            let configs = self.configs.lock();
            if let Some(cfg) = configs.get(name) {
                if let Err(resp) = check_impersonation(
                    peer_uid,
                    peer_gid,
                    cfg.uid.unwrap_or(peer_uid),
                    cfg.gid,
                    name,
                ) {
                    return resp;
                }
            }
        }
        // Attempt to reload the config from disk before checking state
        let mut config = {
            let mut configs = self.configs.lock();
            // If we have a source path, reload it
            if let Some(cfg) = configs.get(name) {
                if let Some(path) = &cfg.source_path {
                    let source_path = std::path::PathBuf::from(path);
                    let on_demand_candidates = config::on_demand_config_candidates(name);
                    let is_on_demand = on_demand_candidates.contains(&source_path);
                    let reload_path = if is_on_demand {
                        config::select_on_demand_config(name).unwrap_or(source_path)
                    } else {
                        source_path
                    };
                    match config::load_app_config(&reload_path) {
                        Ok(mut new_cfg) => {
                            if is_on_demand && unsafe { libc::getuid() } == 0 {
                                match config::resolve_or_create_app_identity(name) {
                                    Ok(identity) => {
                                        new_cfg.uid = Some(identity.uid);
                                        new_cfg.gid = Some(identity.gid);
                                    }
                                    Err(e) => {
                                        return Response::err(format!(
                                            "failed to resolve app identity for '{}': {}",
                                            name, e
                                        ));
                                    }
                                }
                                new_cfg.user = None;
                                new_cfg.group = None;
                            }
                            debug!(
                                "Reloaded config for {} from {}",
                                name,
                                reload_path.display()
                            );
                            configs.insert(name.to_string(), new_cfg.clone());
                            new_cfg
                        }
                        Err(e) => {
                            warn!("Failed to reload config for {}, using cached: {}", name, e);
                            cfg.clone()
                        }
                    }
                } else {
                    cfg.clone()
                }
            } else {
                if let Some(service_path) = config::select_on_demand_config(name) {
                    match config::load_app_config(&service_path) {
                        Ok(mut new_cfg) => {
                            // In root mode, app identity is owned by /home/<service>
                            // and persisted in /home/system/etc/uidmap when needed.
                            if unsafe { libc::getuid() } == 0 {
                                match config::resolve_or_create_app_identity(name) {
                                    Ok(identity) => {
                                        new_cfg.uid = Some(identity.uid);
                                        new_cfg.gid = Some(identity.gid);
                                    }
                                    Err(e) => {
                                        return Response::err(format!(
                                            "failed to resolve app identity for '{}': {}",
                                            name, e
                                        ));
                                    }
                                }
                                new_cfg.user = None;
                                new_cfg.group = None;
                            }

                            info!(
                                "Loaded on-demand config for '{}' from {}",
                                name,
                                service_path.display()
                            );
                            configs.insert(name.to_string(), new_cfg.clone());
                            new_cfg
                        }
                        Err(e) => {
                            return Response::err(format!(
                                "failed to load user config for '{}': {}",
                                name, e
                            ));
                        }
                    }
                } else {
                    return Response::err(format!("no config found for service '{}'", name));
                }
            }
        };

        // A5: Re-check authorization against the freshly loaded/reloaded config.
        // The config was just reloaded from disk (or loaded for the first time
        // from USER_INIT). Its `uid` may differ from the cached copy used for
        // the initial auth check above. A non-privileged peer must not benefit
        // from a config that resolves to a different UID.
        if let Err(resp) = check_impersonation(
            peer_uid,
            peer_gid,
            config.uid.unwrap_or(peer_uid),
            config.gid,
            name,
        ) {
            return resp;
        }

        // Determine if already running and if config changed
        let mut should_restart = false;
        {
            let services = self.services.lock();
            if let Some(proc) = services.get(name)
                && proc.state == ServiceState::Running
            {
                if proc.config != config {
                    info!("Config for '{}' changed, will restart", name);
                    should_restart = true;
                } else {
                    return Response::ok_with_data(
                        serde_json::json!({"pid": proc.pid, "already_running": true}),
                    );
                }
            }
        }

        // If running but config changed, restart it by updating the config in place,
        // sending SIGTERM, and letting the restart loop bring it back with the new config.
        if should_restart {
            let maybe_pid = {
                let mut services = self.services.lock();
                if let Some(proc) = services.get_mut(name) {
                    proc.config = config.clone();
                    proc.state = ServiceState::Stopping;
                    // Don't change target_state so it restarts
                    proc.consecutive_failures = 0;
                    proc.next_restart_at = None;
                    proc.pid
                } else {
                    None
                }
            };
            if let Some(pid) = maybe_pid {
                let _ = process::send_signal(pid, libc::SIGTERM);
                return Response::ok_with_data(serde_json::json!({"restarting": true}));
            }
        }

        // Merge extra args and caller env.
        config.args.extend(extra_args);
        scrub_dangerous_env(&mut extra_env, &config);
        config.env.extend(extra_env);
        apply_activation_context_env(&mut config, context);

        // Check resource availability
        if let Some(ref rm) = self.resource_manager
            && !rm.can_start(&config)
        {
            return Response::err("insufficient resources to start service");
        }

        {
            let mut services = self.services.lock();
            if let Some(proc) = services.get_mut(name) {
                proc.consecutive_failures = 0;
            }
        }

        match self.start_service_with_config(config, None) {
            Ok(pid) => Response::ok_with_data(serde_json::json!({"pid": pid})),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_start_terminal(
        &self,
        name: &str,
        home: &str,
        uid: u32,
        gid: Option<u32>,
        pty: bool,
        mut extra_env: HashMap<String, String>,
        context: Option<ActivationContext>,
        command: Option<String>,
        mut fds: Vec<OwnedFd>,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Response {
        if let Err(reason) = crate::config::validate_cgroup_name(name) {
            return Response::err(format!("invalid service name: {reason}"));
        }
        // Authorization: a non-privileged peer may only spawn processes as
        // itself. Privileged UIDs (root, system, sshd — see `privileged_uids`)
        // may target any UID. This prevents privilege escalation where an
        // authorized non-privileged peer requests uid=0.
        if let Err(resp) = check_impersonation(peer_uid, peer_gid, uid, gid, name) {
            return resp;
        }
        let home_path = std::path::Path::new(home);
        if !home_path.is_dir() {
            return Response::err(format!("home directory '{}' does not exist", home));
        }
        // A16: Validate that the home directory is owned by the target
        // UID. Otherwise a privileged peer (sshd, ssh-mesh) could set HOME
        // to any directory, influencing the child's startup scripts.
        if let Ok(metadata) = std::fs::metadata(home_path) {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != uid {
                return Response::err(format!(
                    "home directory '{}' is owned by UID {}, not the target UID {}",
                    home,
                    metadata.uid(),
                    uid
                ));
            }
        }

        let mut config = {
            let configs = self.configs.lock();
            configs.get(name).cloned()
        }
        .unwrap_or_else(|| {
            let current_uid = unsafe { libc::getuid() };
            let current_gid = unsafe { libc::getgid() };
            let run_as_uid = if current_uid == 0 { uid } else { current_uid };
            let run_as_gid = if current_uid == 0 {
                gid.unwrap_or(uid)
            } else {
                current_gid
            };

            let mut env = HashMap::new();
            env.insert("HOME".to_string(), home.to_string());
            env.insert("USER".to_string(), name.to_string());
            env.insert("LOGNAME".to_string(), name.to_string());
            let shell = preferred_shell();
            env.insert("SHELL".to_string(), shell.to_string());
            env.insert("TERM".to_string(), "xterm-256color".to_string());

            AppConfig {
                name: name.to_string(),
                command: shell.to_string(),
                args: vec!["-l".to_string()],
                uid: Some(run_as_uid),
                gid: Some(run_as_gid),
                user: None,
                group: None,
                env,
                oneshot: true,
                ..Default::default()
            }
        });

        if config.uid.is_none() {
            config.uid = Some(if unsafe { libc::getuid() } == 0 {
                uid
            } else {
                unsafe { libc::getuid() }
            });
        }
        if config.gid.is_none() {
            config.gid = Some(if unsafe { libc::getuid() } == 0 {
                gid.unwrap_or(uid)
            } else {
                unsafe { libc::getgid() }
            });
        }
        config
            .env
            .entry("HOME".to_string())
            .or_insert_with(|| home.to_string());
        config
            .env
            .entry("USER".to_string())
            .or_insert_with(|| name.to_string());
        config
            .env
            .entry("LOGNAME".to_string())
            .or_insert_with(|| name.to_string());
        scrub_dangerous_env(&mut extra_env, &config);
        config.env.extend(extra_env);
        apply_activation_context_env(&mut config, context);

        if let Some(command) = command {
            config.command = preferred_shell().to_string();
            config.args = vec!["-c".to_string(), command];
            config.oneshot = true;
        }

        // Final authorization guard on the resolved config. The config file
        // may have specified a uid different from the request; a non-privileged
        // peer must not benefit from that.
        if let Err(resp) = check_impersonation(
            peer_uid,
            peer_gid,
            config.uid.unwrap_or(peer_uid),
            config.gid,
            name,
        ) {
            return resp;
        }

        let cg =
            crate::cgroup::create_cgroup(name).unwrap_or_else(|_| "/sys/fs/cgroup".to_string());
        let (retained_pty, activation_fd) = if pty {
            if fds.len() != 1 {
                return Response::err(format!("pty terminal expected 1 fd, got {}", fds.len()));
            }
            let fd = fds.pop().expect("one fd");
            let retained_pty = match fd.try_clone() {
                Ok(fd) => Some(fd),
                Err(e) => return Response::err(format!("failed to retain PTY fd: {}", e)),
            };
            (retained_pty, process::ActivationFd::Pty(fd))
        } else if fds.len() == 1 {
            (
                None,
                process::ActivationFd::Stdio(fds.pop().expect("one fd")),
            )
        } else if fds.len() == 3 {
            let stderr = fds.pop().expect("stderr fd");
            let stdout = fds.pop().expect("stdout fd");
            let stdin = fds.pop().expect("stdin fd");
            (
                None,
                process::ActivationFd::StdioPipes {
                    stdin,
                    stdout,
                    stderr,
                },
            )
        } else {
            return Response::err(format!(
                "stdio terminal expected 1 or 3 fds, got {}",
                fds.len()
            ));
        };

        match process::spawn_process(&config, &cg, Some(activation_fd)) {
            Ok((pid, _)) => {
                if let Some(ref tracked) = *self.tracked_child_pids.lock() {
                    tracked.lock().insert(pid);
                }
                let terminal_id = format!(
                    "term-{}",
                    self.next_terminal_id.fetch_add(1, Ordering::Relaxed)
                );
                self.terminal_sessions.lock().insert(
                    terminal_id.clone(),
                    TerminalSession {
                        name: name.to_string(),
                        pid,
                        pty_fd: retained_pty,
                        pidfd: process::open_pidfd(pid).ok(),
                    },
                );
                Response::ok_with_data(serde_json::json!({
                    "pid": pid,
                    "terminal_id": terminal_id
                }))
            }
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_terminal_resize(
        &self,
        terminal_id: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> Response {
        let terminals = self.terminal_sessions.lock();
        let Some(session) = terminals.get(terminal_id) else {
            return Response::err(format!("terminal session '{}' not found", terminal_id));
        };
        let Some(fd) = session.pty_fd.as_ref() else {
            return Response::err(format!("terminal session '{}' has no PTY", terminal_id));
        };

        let mut winsize = libc::winsize {
            ws_row: row_height as u16,
            ws_col: col_width as u16,
            ws_xpixel: pix_width as u16,
            ws_ypixel: pix_height as u16,
        };
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &mut winsize) };
        if rc < 0 {
            return Response::err(format!(
                "failed to resize terminal '{}': {}",
                terminal_id,
                std::io::Error::last_os_error()
            ));
        }

        Response::ok_with_data(serde_json::json!({"terminal_id": terminal_id}))
    }

    fn handle_terminal_command(
        &self,
        terminal_id: &str,
        command: &str,
        data: serde_json::Value,
    ) -> Response {
        let signal = match command {
            "close" | "hup" => Some(libc::SIGHUP),
            "signal" => data
                .get("signal")
                .and_then(serde_json::Value::as_i64)
                .map(|signal| signal as i32),
            _ => {
                return Response::err(format!(
                    "unsupported terminal command '{}' for '{}'",
                    command, terminal_id
                ));
            }
        };

        let Some(signal) = signal else {
            return Response::err(format!(
                "terminal command '{}' for '{}' requires a signal",
                command, terminal_id
            ));
        };

        let (pid, pidfd) = {
            let mut terminals = self.terminal_sessions.lock();
            let Some(session) = terminals.get_mut(terminal_id) else {
                return Response::err(format!("terminal session '{}' not found", terminal_id));
            };
            (session.pid, session.pidfd.take())
        };

        match process::send_signal_pidfd(pidfd.as_ref(), pid, signal) {
            Ok(()) => Response::ok_with_data(serde_json::json!({
                "terminal_id": terminal_id,
                "pid": pid,
                "signal": signal
            })),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn prepare_activation_context(&self, name: String, context: ActivationContext) -> Response {
        let mut pending = self.pending_activation_contexts.lock();
        // Enforce a global cap across all services to prevent unbounded
        // HashMap growth from a peer creating contexts under many distinct
        // service names.
        const MAX_TOTAL_PENDING_CONTEXTS: usize = 1024;
        let total: usize = pending.values().map(|q| q.len()).sum();
        if total >= MAX_TOTAL_PENDING_CONTEXTS {
            warn!(
                "Refusing activation context for '{}': total pending contexts already at cap {}",
                name, MAX_TOTAL_PENDING_CONTEXTS
            );
            return Response::err(format!(
                "pending activation context cap of {MAX_TOTAL_PENDING_CONTEXTS} reached"
            ));
        }
        let queue = pending.entry(name).or_default();
        queue.push_back(context);
        while queue.len() > 32 {
            queue.pop_front();
        }
        Response::ok()
    }

    pub fn take_activation_context(&self, name: &str) -> Option<ActivationContext> {
        let mut pending = self.pending_activation_contexts.lock();
        let context = pending.get_mut(name).and_then(VecDeque::pop_front);
        if pending.get(name).is_some_and(VecDeque::is_empty) {
            pending.remove(name);
        }
        context
    }

    async fn handle_stop(
        &self,
        name: &str,
        signal: Option<i32>,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Response {
        if let Err(reason) = crate::config::validate_cgroup_name(name) {
            return Response::err(format!("invalid service name: {reason}"));
        }
        let (pid, network_pid, pidfd, config) = {
            let mut services = self.services.lock();
            match services.get_mut(name) {
                Some(proc)
                    if proc.state == ServiceState::Running
                        || proc.state == ServiceState::Frozen =>
                {
                    // Authorization: a non-privileged peer may only stop
                    // services running as its own UID.
                    let svc_uid = proc.config.uid.unwrap_or(peer_uid);
                    let svc_gid = proc.config.gid;
                    if let Err(resp) =
                        check_impersonation(peer_uid, peer_gid, svc_uid, svc_gid, name)
                    {
                        return resp;
                    }
                    proc.state = ServiceState::Stopping;
                    proc.target_state = ServiceState::Stopped;
                    proc.netns_fd = None;
                    proc.userns_fd = None;
                    proc.namespace_pid = None;
                    proc.mesh_tun_attached = false;
                    let pidfd = proc.pidfd.take();
                    (proc.pid, proc.network_pid, pidfd, proc.config.clone())
                }
                Some(_) => return Response::err(format!("service '{}' is not running", name)),
                None => return Response::err(format!("service '{}' not found", name)),
            }
        };

        if let Err(e) = run_service_commands(
            &config,
            &config.exec_stop,
            "ExecStop",
            config.timeout_stop_sec,
        ) {
            error!("ExecStop failed for '{}': {}", name, e);
            return Response::err(e.to_string());
        }

        if let Some(network_pid) = network_pid {
            let _ = process::send_signal(network_pid, libc::SIGTERM);
        }
        if let Some(pid) = pid
            && config.kill_mode != crate::config::KillMode::None
            && let Err(e) = process::stop_process(
                pid,
                pidfd.as_ref(),
                signal.or(Some(config.kill_signal)),
                config.timeout_stop_sec,
                config.send_sigkill,
            )
            .await
        {
            error!("Failed to stop '{}': {}", name, e);
            return Response::err(e.to_string());
        }

        // Update state
        {
            let mut services = self.services.lock();
            if let Some(proc) = services.get_mut(name) {
                proc.state = ServiceState::Stopped;
                proc.pid = None;
                proc.network_pid = None;
                proc.netns_fd = None;
                proc.userns_fd = None;
                proc.namespace_pid = None;
                proc.mesh_tun_attached = false;
            }
        }
        self.notify_service_exit(name);

        info!("Stopped service '{}'", name);
        Response::ok()
    }

    fn handle_freeze(&self, name: &str, peer_uid: u32, peer_gid: u32) -> Response {
        if let Err(reason) = crate::config::validate_cgroup_name(name) {
            return Response::err(format!("invalid service name: {reason}"));
        }
        let mut services = self.services.lock();
        let proc = match services.get_mut(name) {
            Some(p) if p.state == ServiceState::Running => p,
            Some(_) => return Response::err(format!("service '{}' is not running", name)),
            None => return Response::err(format!("service '{}' not found", name)),
        };
        // Authorization: a non-privileged peer may only freeze services
        // running as its own UID.
        let svc_uid = proc.config.uid.unwrap_or(peer_uid);
        let svc_gid = proc.config.gid;
        if let Err(resp) = check_impersonation(peer_uid, peer_gid, svc_uid, svc_gid, name) {
            return resp;
        }

        if let Some(pid) = proc.pid {
            if let Err(e) = process::freeze_process(pid, proc.cgroup_path.as_deref()) {
                return Response::err(e.to_string());
            }
            proc.state = ServiceState::Frozen;
            info!("Froze service '{}'", name);
        }

        Response::ok()
    }

    fn handle_unfreeze(&self, name: &str, peer_uid: u32, peer_gid: u32) -> Response {
        if let Err(reason) = crate::config::validate_cgroup_name(name) {
            return Response::err(format!("invalid service name: {reason}"));
        }
        let mut services = self.services.lock();
        let proc = match services.get_mut(name) {
            Some(p) if p.state == ServiceState::Frozen => p,
            Some(_) => return Response::err(format!("service '{}' is not frozen", name)),
            None => return Response::err(format!("service '{}' not found", name)),
        };
        // Authorization: a non-privileged peer may only unfreeze services
        // running as its own UID.
        let svc_uid = proc.config.uid.unwrap_or(peer_uid);
        let svc_gid = proc.config.gid;
        if let Err(resp) = check_impersonation(peer_uid, peer_gid, svc_uid, svc_gid, name) {
            return resp;
        }

        if let Some(pid) = proc.pid {
            if let Err(e) = process::unfreeze_process(pid, proc.cgroup_path.as_deref()) {
                return Response::err(e.to_string());
            }
            proc.state = ServiceState::Running;
            info!("Unfroze service '{}'", name);
        }

        Response::ok()
    }

    fn handle_status(&self, name: Option<&str>) -> Response {
        let services = self.services.lock();

        match name {
            Some(name) => match services.get(name) {
                Some(proc) => {
                    let status = proc.status();
                    Response::ok_with_data(serde_json::to_value(status).unwrap_or_default())
                }
                None => Response::err(format!("service '{}' not found", name)),
            },
            None => {
                // All services
                let statuses: Vec<ServiceStatus> = services.values().map(|p| p.status()).collect();
                Response::ok_with_data(serde_json::to_value(statuses).unwrap_or_default())
            }
        }
    }

    fn handle_observer_processes(&self) -> Response {
        let processes = self.observer.get_all_processes(1);
        Response::ok_with_data(serde_json::json!(
            processes.into_values().collect::<Vec<_>>()
        ))
    }

    fn handle_observer_process(&self, pid: u32) -> Response {
        match self.observer.get_process(pid) {
            Some(process) => {
                let cgroup = process
                    .cgroup_path
                    .as_ref()
                    .and_then(|p| observer::read_cgroup_detailed(p));
                let parent_cgroups = process
                    .cgroup_path
                    .as_ref()
                    .map(|p| observer::get_parent_cgroups(p))
                    .unwrap_or_default();
                Response::ok_with_data(serde_json::json!(ProcessDetailedInfo {
                    process,
                    cgroup,
                    parent_cgroups,
                }))
            }
            None => Response::err(format!("process {pid} not found")),
        }
    }

    fn handle_observer_process_only(&self, pid: u32) -> Response {
        match self.observer.get_process(pid) {
            Some(process) => Response::ok_with_data(serde_json::json!(process)),
            None => Response::err(format!("process {pid} not found")),
        }
    }

    fn handle_observer_cgroups(&self) -> Response {
        Response::ok_with_data(serde_json::json!(self.observer.get_all_cgroups()))
    }

    fn handle_observer_cgroup(&self, path: &str) -> Response {
        match observer::read_cgroup_detailed(path) {
            Some(cgroup) => Response::ok_with_data(serde_json::json!(cgroup)),
            None => Response::err(format!("cgroup {path} not found")),
        }
    }

    fn handle_observer_pressure(&self) -> Response {
        Response::ok_with_data(serde_json::json!(self.observer.get_psi_watches()))
    }

    fn handle_observer_cgroup_high(
        &self,
        path: String,
        percentage: f64,
        interval: u64,
        peer_uid: u32,
    ) -> Response {
        if let Err(resp) = require_system_or_root(peer_uid) {
            return resp;
        }
        match self
            .observer
            .adjust_cgroup_memory_high(path, percentage, interval)
        {
            Ok(()) => Response::ok(),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_observer_cgroup_procs(&self, path: &str) -> Response {
        Response::ok_with_data(serde_json::json!(
            self.observer.get_processes_in_cgroup(path)
        ))
    }

    fn handle_observer_move_process(
        &self,
        pid: u32,
        cgroup_name: Option<String>,
        peer_uid: u32,
    ) -> Response {
        if let Err(resp) = require_system_or_root(peer_uid) {
            return resp;
        }
        match self.observer.move_process_to_cgroup(pid, cgroup_name) {
            Ok(()) => Response::ok(),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_observer_clear_refs(&self, pid: u32, value: &str, peer_uid: u32) -> Response {
        if let Err(resp) = require_system_or_root(peer_uid) {
            return resp;
        }
        match self.observer.clear_refs(pid, value) {
            Ok(()) => Response::ok_with_data(serde_json::json!({
                "message": format!("cleared refs for process {pid} with value {value}")
            })),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_observer_freeze_process(&self, pid: u32, freeze: bool, peer_uid: u32) -> Response {
        if let Err(resp) = require_system_or_root(peer_uid) {
            return resp;
        }
        match self.observer.freeze_process(pid, freeze) {
            Ok(()) => Response::ok(),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_observer_freeze_cgroup(&self, path: &str, freeze: bool, peer_uid: u32) -> Response {
        if let Err(resp) = require_system_or_root(peer_uid) {
            return resp;
        }
        match self.observer.freeze_cgroup(path, freeze) {
            Ok(()) => Response::ok(),
            Err(e) => Response::err(e.to_string()),
        }
    }

    async fn handle_shutdown(&self) -> Response {
        info!("Shutdown requested");
        self.shutdown().await;
        // Exit the process since the accept loop has no clean break mechanism
        std::process::exit(0);
    }

    fn handle_reload(&self) -> Response {
        info!("Reloading all system configurations");

        // Reload from disk
        let dirs: Vec<&str> = self.config.config_dirs.iter().map(|s| s.as_str()).collect();
        let loaded_configs = config::load_system_configs(&dirs);

        let mut changed = 0;
        let mut configs = self.configs.lock();
        let mut services = self.services.lock();
        let mut reload_commands = Vec::new();

        for new_cfg in loaded_configs {
            let name = new_cfg.name.clone();
            let is_changed = match configs.get(&name) {
                Some(old_cfg) => {
                    if *old_cfg == new_cfg {
                        if services
                            .get(&name)
                            .is_some_and(|proc| proc.state == ServiceState::Running)
                        {
                            reload_commands.push(new_cfg.clone());
                        }
                        false
                    } else {
                        true
                    }
                }
                None => true,
            };

            if is_changed {
                info!("Config for '{}' changed or is new during reload", name);
                configs.insert(name.clone(), new_cfg.clone());
                changed += 1;

                // Stop active process so it restarts with new config
                if let Some(proc) = services.get_mut(&name)
                    && proc.state == ServiceState::Running
                {
                    proc.config = new_cfg.clone();
                    proc.state = ServiceState::Stopping;
                    // Keep target_state running so it gets restarted!
                    proc.consecutive_failures = 0;
                    proc.next_restart_at = None;
                    if let Some(pid) = proc.pid {
                        let _ = process::send_signal(pid, libc::SIGTERM);
                    }
                }
            }
        }
        drop(services);
        drop(configs);

        for config in reload_commands {
            if let Err(e) = run_service_commands(
                &config,
                &config.exec_reload,
                "ExecReload",
                config.timeout_start_sec,
            ) {
                warn!("ExecReload failed for '{}': {}", config.name, e);
            }
        }

        Response::ok_with_data(serde_json::json!({"reloaded": true, "changed": changed}))
    }

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    fn handle_child_exit(&self, pid: u32, exit_code: i32) {
        crate::activation::reclaim_inetd_permit(pid);
        let removed_terminals: Vec<String> = {
            let mut terminals = self.terminal_sessions.lock();
            let ids: Vec<String> = terminals
                .iter()
                .filter_map(|(id, session)| {
                    if session.pid == pid {
                        Some(id.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for id in &ids {
                if let Some(session) = terminals.remove(id) {
                    debug!(
                        "Terminal session '{}' for '{}' exited with PID {}",
                        id, session.name, pid
                    );
                }
            }
            ids
        };
        if !removed_terminals.is_empty() {
            debug!(
                "Removed terminal sessions for PID {}: {:?}",
                pid, removed_terminals
            );
        }

        let mut services = self.services.lock();
        for (name, proc) in services.iter_mut() {
            if proc.network_pid == Some(pid) {
                info!(
                    "Network sidecar for service '{}' (PID {}) exited with code {}",
                    name, pid, exit_code
                );
                proc.network_pid = None;
                if proc.pid.is_none() {
                    if let Some(ref cg) = proc.cgroup_path.take() {
                        let _ = crate::cgroup::remove_cgroup(cg);
                    }
                }
                return;
            }

            if proc.pid == Some(pid) {
                let intentionally_stopped = proc.target_state == ServiceState::Stopped;
                info!(
                    "Service '{}' (PID {}) exited with code {}. Intentional: {}",
                    name, pid, exit_code, intentionally_stopped
                );

                proc.state = ServiceState::Stopped;
                proc.pid = None;
                proc.netns_fd = None;
                proc.userns_fd = None;
                proc.namespace_pid = None;
                proc.mesh_tun_attached = false;
                if let Some(network_pid) = proc.network_pid {
                    let _ = process::send_signal(network_pid, libc::SIGTERM);
                }

                if proc.network_pid.is_none() {
                    if let Some(ref cg) = proc.cgroup_path.take() {
                        let _ = crate::cgroup::remove_cgroup(cg);
                    }
                }

                self.notify_service_exit(name);

                let should_restart = if intentionally_stopped {
                    false
                } else if proc.config.oneshot {
                    // For oneshot, only restart if specifically configured to do so
                    should_restart_for_policy(proc.config.restart, exit_code)
                } else {
                    should_restart_for_policy(proc.config.restart, exit_code)
                };

                if should_restart {
                    // crashed or was killed for restart!
                    let running_duration = proc.started_at.map(|t| t.elapsed()).unwrap_or_default();
                    if running_duration >= std::time::Duration::from_secs(10) {
                        proc.consecutive_failures = 1;
                    } else {
                        proc.consecutive_failures += 1;
                    }

                    if let Some(max_retries) = proc.config.backoff.max_retries {
                        if proc.consecutive_failures > max_retries {
                            warn!(
                                "Service '{}' crashed {} times, exceeding max_retries ({}). Marking as stopped.",
                                name, proc.consecutive_failures, max_retries
                            );
                            proc.target_state = ServiceState::Stopped;
                            if let Some(ref cg) = proc.cgroup_path.take() {
                                let _ = crate::cgroup::remove_cgroup(cg);
                            }
                            return;
                        }
                    }

                    let backoff_secs = calculate_backoff(&proc.config, proc.consecutive_failures);
                    let restart_delay_secs = restart_delay_with_jitter(name, backoff_secs.max(proc.config.restart_sec));

                    info!(
                        "Service '{}' crashed. Scheduling restart #{} in {}s",
                        name, proc.consecutive_failures, restart_delay_secs
                    );

                    proc.next_restart_at = Some(
                        std::time::Instant::now()
                            + std::time::Duration::from_secs(restart_delay_secs),
                    );
                } else {
                    proc.target_state = ServiceState::Stopped;
                }

                return;
            }
        }
        debug!("Unmanaged child PID {} exited with code {}", pid, exit_code);
    }

    fn check_restarts(&self) {
        let now = std::time::Instant::now();
        let mut to_restart = Vec::new();

        {
            let mut services = self.services.lock();
            for (_name, proc) in services.iter_mut() {
                if proc.state == ServiceState::Stopped
                    && proc.target_state == ServiceState::Running
                    && proc.pid.is_none()
                {
                    if let Some(next_at) = proc.next_restart_at {
                        if now >= next_at {
                            to_restart.push(proc.config.clone());
                            proc.state = ServiceState::Starting;
                            proc.next_restart_at = None;
                        }
                    } else {
                        // Immediate restart (should only occur if just loaded without backoff)
                        to_restart.push(proc.config.clone());
                        proc.state = ServiceState::Starting;
                    }
                }
            }

            for (name, proc) in services.iter_mut() {
                if proc.state == ServiceState::Running {
                    // --- Watchdog Check ---
                    if let Some(watchdog_sec) = proc.config.watchdog_sec {
                        let mut check_watchdog = true;
                        // Grace period: don't check watchdog until started_at + watchdog_sec has passed
                        if let Some(started) = proc.started_at {
                            if now.duration_since(started) < std::time::Duration::from_secs(watchdog_sec) {
                                check_watchdog = false;
                            }
                        }
                        // Skip watchdog if ReadyMatch is configured but the service isn't ready yet
                        if proc.config.ready_match.is_some() && !proc.ready {
                            check_watchdog = false;
                        }

                        if check_watchdog {
                            let last_ping = proc.last_watchdog_ping.unwrap_or(proc.started_at.unwrap_or(now));
                            if now.duration_since(last_ping) > std::time::Duration::from_secs(watchdog_sec) {
                                warn!(
                                    "Service '{}' watchdog timeout ({}s without health output matching '{}')",
                                    name,
                                    watchdog_sec,
                                    proc.config.watchdog_match.as_deref().unwrap_or("active")
                                );
                                if let Some(pid) = proc.pid {
                                    let _ = process::send_signal(pid, libc::SIGKILL);
                                }
                            }
                        }
                    }

                    // --- Idle Termination Check ---
                    if let Some(idle_sec) = proc.config.idle_termination_sec {
                        let metrics_idle = proc.last_active == Some(0) && proc.last_sess.unwrap_or(0) == 0;
                        let stderr_idle = proc.last_stderr_at
                            .map(|t| now.duration_since(t) >= std::time::Duration::from_secs(idle_sec))
                            .unwrap_or(false);

                        if metrics_idle && stderr_idle {
                            if proc.idle_since.is_none() {
                                proc.idle_since = Some(now);
                            }
                            if let Some(idle_start) = proc.idle_since {
                                if now.duration_since(idle_start) >= std::time::Duration::from_secs(idle_sec) {
                                    info!(
                                        "Service '{}' idle for {}s (active=0, no output), terminating",
                                        name, idle_sec
                                    );
                                    proc.target_state = ServiceState::Stopped;
                                    if let Some(pid) = proc.pid {
                                        let _ = process::send_signal(pid, proc.config.kill_signal);
                                    }
                                }
                            }
                        } else {
                            proc.idle_since = None;
                        }
                    }
                }
            }
        }

        for config in to_restart {
            info!("Restarting service '{}'", config.name);
            if let Some(ref rm) = self.resource_manager
                && !rm.can_start(&config)
            {
                warn!("Insufficient resources for restarting '{}'", config.name);
                let mut s = self.services.lock();
                if let Some(proc) = s.get_mut(&config.name) {
                    proc.state = ServiceState::Stopped;
                    proc.next_restart_at = Some(now + std::time::Duration::from_secs(10));
                }
                continue;
            }

            match self.start_service_with_config(config.clone(), None) {
                Ok(_) => {
                    let mut s = self.services.lock();
                    if let Some(proc) = s.get_mut(&config.name) {
                        proc.restarts += 1;
                    }
                }
                Err(e) => {
                    error!("Failed to restart '{}': {}", config.name, e);
                    let mut s = self.services.lock();
                    if let Some(proc) = s.get_mut(&config.name) {
                        proc.state = ServiceState::Stopped;
                        // Increase failure count
                        proc.consecutive_failures += 1;
                        let backoff_secs =
                            calculate_backoff(&proc.config, proc.consecutive_failures);
                        let restart_delay_secs =
                            restart_delay_with_jitter(&config.name, backoff_secs);
                        proc.next_restart_at = Some(
                            std::time::Instant::now()
                                + std::time::Duration::from_secs(restart_delay_secs),
                        );
                    }
                }
            }
        }
    }

    /// Start a service by name using the pre-loaded config.
    fn start_service_internal(&self, name: &str) -> Result<u32> {
        let config = self
            .configs
            .lock()
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no config for '{}'", name))?;

        self.start_service_with_config(config, None)
    }

    /// Start a service from a config.
    pub fn start_service_with_config(
        &self,
        config: AppConfig,
        passed_fd: Option<crate::process::ActivationFd>,
    ) -> Result<u32> {
        let name = config.name.clone();

        run_service_commands(
            &config,
            &config.exec_start_pre,
            "ExecStartPre",
            config.timeout_start_sec,
        )?;

        // Create cgroup
        let cgroup_path = match crate::cgroup::create_cgroup(&name) {
            Ok(path) => {
                // Set limits
                if let Err(e) = crate::cgroup::set_limits(&path, &config.resources) {
                    warn!("Failed to set cgroup limits for '{}': {}", name, e);
                }
                Some(path)
            }
            Err(e) => {
                warn!(
                    "Failed to create cgroup for '{}': {} (proceeding without cgroup)",
                    name, e
                );
                None
            }
        };

        let cg = cgroup_path.as_deref().unwrap_or("/sys/fs/cgroup");

        // B9: Guard against double-spawn. If another caller (e.g. check_restarts)
        // already transitioned this service to `Starting`, refuse to spawn again
        // to avoid two processes for the same service.
        {
            let services = self.services.lock();
            if let Some(proc) = services.get(&name) {
                if proc.state == ServiceState::Starting && proc.pid.is_none() {
                    return Err(anyhow::anyhow!(
                        "service '{}' is already starting (double-spawn prevented)",
                        name
                    ));
                }
                if proc.state == ServiceState::Running && proc.pid.is_some() {
                    // Already running; let the caller decide via handle_start's
                    // restart logic. Return the existing pid.
                    if let Some(pid) = proc.pid {
                        return Ok(pid);
                    }
                }
            }
        }

        // B5: Register the service in `Starting` state BEFORE spawning, so
        // that the SIGCHLD reaper can match a fast-exiting child's PID. If the
        // child exits before we insert, the exit event is lost and the daemon
        // believes a dead service is Running.
        {
            let mut services = self.services.lock();
            if let Some(proc) = services.get_mut(&name) {
                proc.state = ServiceState::Starting;
                proc.target_state = ServiceState::Running;
                proc.pid = None;
                proc.network_pid = None;
                proc.netns_fd = None;
                proc.userns_fd = None;
                proc.namespace_pid = None;
                proc.mesh_tun_attached = false;
            } else {
                let mut proc = ManagedProcess::new(config.clone());
                proc.state = ServiceState::Starting;
                proc.target_state = ServiceState::Running;
                services.insert(name.clone(), proc);
            }
        }

        // Spawn process
        let (pid, stderr) = match process::spawn_process(&config, cg, passed_fd) {
            Ok(pair) => pair,
            Err(e) => {
                // Spawn failed: mark the service Stopped so it can be restarted.
                let mut services = self.services.lock();
                if let Some(proc) = services.get_mut(&name) {
                    proc.state = ServiceState::Stopped;
                    proc.pid = None;
                    if !should_restart_for_policy(proc.config.restart, -1) {
                        proc.target_state = ServiceState::Stopped;
                    }
                }
                return Err(e.into());
            }
        };

        let network_sidecar = match crate::network::start_network_sidecar(&config, pid, cg) {
            Ok(sidecar) => sidecar,
            Err(error) => {
                let _ = process::send_signal(pid, libc::SIGTERM);
                let mut services = self.services.lock();
                if let Some(proc) = services.get_mut(&name) {
                    proc.state = ServiceState::Stopped;
                    proc.pid = None;
                    proc.network_pid = None;
                    proc.netns_fd = None;
                    proc.userns_fd = None;
                    proc.namespace_pid = None;
                    proc.mesh_tun_attached = false;
                    if !should_restart_for_policy(proc.config.restart, -1) {
                        proc.target_state = ServiceState::Stopped;
                    }
                }
                return Err(error);
            }
        };

        // Register the spawned PID with the reaper (when not in catch-all mode)
        // and update the service state to Running.
        {
            if let Some(ref tracked) = *self.tracked_child_pids.lock() {
                tracked.lock().insert(pid);
                if let Some(sidecar) = &network_sidecar {
                    tracked.lock().insert(sidecar.pid);
                }
            }
            let mut services = self.services.lock();
            if let Some(proc) = services.get_mut(&name) {
                proc.state = ServiceState::Running;
                proc.target_state = ServiceState::Running;
                proc.pid = Some(pid);
                proc.network_pid = network_sidecar.as_ref().map(|sidecar| sidecar.pid);
                proc.started_at = Some(std::time::Instant::now());
                proc.cgroup_path = cgroup_path;
                proc.config = config.clone();
                proc.ready = config.ready_match.is_none();
                proc.last_watchdog_ping = None;
                proc.last_stderr_at = None;
                proc.last_active = None;
                proc.last_sess = None;
                proc.idle_since = None;
                // A10: open a pidfd for PID-safe signaling. On failure
                // (extremely unlikely after spawn succeeded), leave pidfd
                // None; send_signal_pidfd will fall back to kill(2).
                match process::open_pidfd(pid) {
                    Ok(fd) => proc.pidfd = Some(fd),
                    Err(e) => warn!(
                        "open_pidfd for PID {} failed: {}; signals will use kill(2)",
                        pid, e
                    ),
                }
            }
        }
        info!("Service '{}' started with PID {}", name, pid);

        if let Some(stderr_pipe) = stderr {
            let services_clone = self.services.clone();
            spawn_stderr_reader(name.clone(), stderr_pipe, services_clone);
        }

        if let Err(error) = run_service_commands(
            &config,
            &config.exec_start_post,
            "ExecStartPost",
            config.timeout_start_sec,
        ) {
            let _ = process::send_signal(pid, config.kill_signal);
            return Err(error);
        }

        Ok(pid)
    }

    /// Gracefully shut down all services.
    pub async fn shutdown(&self) {
        info!("Shutting down all services");

        if let Some(ref rm) = self.resource_manager {
            rm.stop();
        }

        let names: Vec<String> = self.services.lock().keys().cloned().collect();

        for name in names {
            let pid = {
                let services = self.services.lock();
                services.get(&name).and_then(|p| {
                    if p.state == ServiceState::Running || p.state == ServiceState::Frozen {
                        p.pid
                    } else {
                        None
                    }
                })
            };

            if let Some(pid) = pid {
                debug!("Stopping service '{}' (PID {})", name, pid);
                let (kill_signal, timeout_stop, send_sigkill, pidfd) = {
                    let mut services = self.services.lock();
                    match services.get_mut(&name) {
                        Some(p) => (
                            p.config.kill_signal,
                            p.config.timeout_stop_sec,
                            p.config.send_sigkill,
                            p.pidfd.take(),
                        ),
                        None => (libc::SIGTERM, None, true, None),
                    }
                };
                let _ = process::stop_process(
                    pid,
                    pidfd.as_ref(),
                    Some(kill_signal),
                    timeout_stop,
                    send_sigkill,
                )
                .await;
            }

            let network_pid = {
                let services = self.services.lock();
                services.get(&name).and_then(|p| p.network_pid)
            };
            if let Some(pid) = network_pid {
                debug!("Stopping network sidecar for '{}' (PID {})", name, pid);
                let _ = process::send_signal(pid, libc::SIGTERM);
            }

            // Clean up cgroup
            let cgroup_path = {
                let services = self.services.lock();
                services.get(&name).and_then(|p| p.cgroup_path.clone())
            };
            if let Some(ref cg) = cgroup_path {
                let _ = crate::cgroup::remove_cgroup(cg);
            }
        }

        // Clean up socket
        let _ = std::fs::remove_file(&self.config.socket_path);
        let _ = self.shutdown_tx.send(true);
        info!("Daemon shutdown complete");
    }
}

fn restart_delay_with_jitter(service_name: &str, base_secs: u64) -> u64 {
    if base_secs <= 1 {
        return base_secs;
    }

    let jitter_window = (base_secs / 10).clamp(1, 30);
    let mut hasher = DefaultHasher::new();
    service_name.hash(&mut hasher);
    base_secs.saturating_add(hasher.finish() % (jitter_window + 1))
}

fn calculate_backoff(config: &AppConfig, consecutive_failures: u32) -> u64 {
    if consecutive_failures == 0 {
        return 0;
    }
    let initial = config.backoff.initial_secs.max(config.restart_sec);
    let mut backoff_secs = match config.backoff.policy {
        crate::config::BackoffPolicy::Linear => initial.saturating_mul(consecutive_failures as u64),
        crate::config::BackoffPolicy::Exponential => {
            let multiplier = 1_u64
                .checked_shl(consecutive_failures - 1)
                .unwrap_or(u64::MAX);
            initial.saturating_mul(multiplier)
        }
    };

    if config.backoff.max_retries.is_none() {
        backoff_secs = backoff_secs.min(24 * 3600);
    }
    backoff_secs
}

fn spawn_stderr_reader(
    name: String,
    stderr: std::process::ChildStderr,
    services: Arc<Mutex<HashMap<String, ManagedProcess>>>,
) {
    std::thread::spawn(move || {
        use std::io::BufRead;
        let reader = std::io::BufReader::new(stderr);
        for line_result in reader.lines() {
            let line = match line_result {
                Ok(l) => l,
                Err(_) => break,
            };

            // 1. Forward the line to mesh-init's own stderr
            eprintln!("{}: {}", name, line);

            if line.trim().is_empty() {
                continue;
            }

            let now = std::time::Instant::now();
            let mut services_guard = services.lock();
            let Some(proc) = services_guard.get_mut(&name) else {
                break;
            };

            proc.last_stderr_at = Some(now);

            // 3. Detect format
            let is_json = line.trim_start().starts_with('{');

            // 4. Check ReadyMatch
            if let Some(ref ready_match) = proc.config.ready_match {
                if !proc.ready && line.contains(ready_match) {
                    proc.ready = true;
                    info!("Service '{}' is ready (matched '{}')", name, ready_match);
                }
            }

            // 5. Check WatchdogMatch
            if let Some(ref watchdog_match) = proc.config.watchdog_match {
                if line.contains(watchdog_match) {
                    proc.last_watchdog_ping = Some(now);
                }
            }

            // 6. Extract metrics
            let mut active = None;
            let mut sess = None;
            if is_json {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                    if let Some(obj) = v.as_object() {
                        if let Some(a) = obj.get("active").and_then(|a| a.as_u64()) {
                            active = Some(a);
                        }
                        if let Some(s) = obj.get("sess").and_then(|s| s.as_u64()) {
                            sess = Some(s);
                        }
                    }
                }
            } else {
                // logfmt-like token scanning (active=N sess=N)
                // Find active=N
                if let Some(pos) = line.find("active=") {
                    let s = &line[pos + 7..];
                    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if !digits.is_empty() {
                        if let Ok(val) = digits.parse::<u64>() {
                            active = Some(val);
                        }
                    }
                }
                // Find sess=N
                if let Some(pos) = line.find("sess=") {
                    let s = &line[pos + 5..];
                    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if !digits.is_empty() {
                        if let Ok(val) = digits.parse::<u64>() {
                            sess = Some(val);
                        }
                    }
                }
            }

            if active.is_some() {
                proc.last_active = active;
            }
            if sess.is_some() {
                proc.last_sess = sess;
            }
        }
    });
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::sync::Arc;

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    #[test]
    fn test_dangerous_env_filter_drops_default_blocked_names() {
        let _guard = env_lock().lock().unwrap();
        unsafe { std::env::remove_var("MESH_DANGEROUS_ENV") };
        let config = AppConfig::default();
        let mut env = HashMap::from([
            ("APP_MODE".to_string(), "prod".to_string()),
            ("PATH".to_string(), "/tmp/bin".to_string()),
            ("LD_PRELOAD".to_string(), "/tmp/libhack.so".to_string()),
            ("BASH_FUNC_demo%%".to_string(), "() { :; }".to_string()),
        ]);

        scrub_dangerous_env(&mut env, &config);

        assert_eq!(env.get("APP_MODE").map(String::as_str), Some("prod"));
        assert!(!env.contains_key("PATH"));
        assert!(!env.contains_key("LD_PRELOAD"));
        assert!(!env.contains_key("BASH_FUNC_demo%%"));
    }

    #[test]
    fn test_dangerous_env_filter_honors_service_allowlist() {
        let _guard = env_lock().lock().unwrap();
        unsafe { std::env::remove_var("MESH_DANGEROUS_ENV") };
        let config = AppConfig {
            allow_dangerous_env: vec!["PATH".to_string(), "BASH_FUNC_*".to_string()],
            ..Default::default()
        };
        let mut env = HashMap::from([
            ("PATH".to_string(), "/opt/app/bin".to_string()),
            ("LD_PRELOAD".to_string(), "/tmp/libhack.so".to_string()),
            ("BASH_FUNC_demo%%".to_string(), "() { :; }".to_string()),
        ]);

        scrub_dangerous_env(&mut env, &config);

        assert!(env.contains_key("PATH"));
        assert!(env.contains_key("BASH_FUNC_demo%%"));
        assert!(!env.contains_key("LD_PRELOAD"));
    }

    #[test]
    fn test_dangerous_env_filter_uses_global_override() {
        let _guard = env_lock().lock().unwrap();
        unsafe { std::env::set_var("MESH_DANGEROUS_ENV", "SECRET_*,APP_MODE") };
        let config = AppConfig::default();
        let mut env = HashMap::from([
            ("PATH".to_string(), "/tmp/bin".to_string()),
            ("APP_MODE".to_string(), "prod".to_string()),
            ("SECRET_TOKEN".to_string(), "s3cr3t".to_string()),
        ]);

        scrub_dangerous_env(&mut env, &config);

        unsafe { std::env::remove_var("MESH_DANGEROUS_ENV") };
        assert!(env.contains_key("PATH"));
        assert!(!env.contains_key("APP_MODE"));
        assert!(!env.contains_key("SECRET_TOKEN"));
    }

    #[test]
    fn test_activation_context_overrides_caller_metadata_env() {
        let _guard = env_lock().lock().unwrap();
        unsafe { std::env::remove_var("MESH_DANGEROUS_ENV") };
        let mut config = AppConfig {
            env: HashMap::from([("SSH_MESH_ROUTE_USER".to_string(), "spoofed".to_string())]),
            ..Default::default()
        };
        let context = ActivationContext {
            kind: "ssh".to_string(),
            user: "alice".to_string(),
            command: None,
            certificate_user: None,
            peer_key_sha: None,
            client_id: None,
            env: HashMap::new(),
        };

        apply_activation_context_env(&mut config, Some(context));

        assert_eq!(
            config.env.get("SSH_MESH_ROUTE_USER").map(String::as_str),
            Some("alice")
        );
    }

    #[test]
    fn test_daemon_config_loading() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("sleep.toml");
        std::fs::write(
            &config_path,
            r#"
[Service]
ExecStart = "/bin/sleep 10"
OOMScoreAdjust = -700
"#,
        )
        .unwrap();

        let configs = config::load_system_configs(&[dir.path().to_str().unwrap()]);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "sleep");
        assert_eq!(configs[0].priority, 300);
        assert_eq!(configs[0].command, "/bin/sleep");
    }

    #[test]
    fn test_daemon_creation() {
        let cfg = DaemonConfig {
            config_dirs: vec!["/nonexistent".to_string()],
            socket_path: "/tmp/mesh-init-test.sock".to_string(),
        };
        let daemon = Daemon::new(cfg);
        assert!(daemon.services.lock().is_empty());
    }

    #[tokio::test]
    async fn test_start_terminal_uses_named_config_and_passed_fd() {
        let cfg = DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test.sock".to_string(),
        };
        let daemon = Daemon::new(cfg);
        let tracked = Arc::new(parking_lot::Mutex::new(HashSet::new()));
        *daemon.tracked_child_pids.lock() = Some(tracked.clone());
        let current_uid = unsafe { libc::getuid() };
        let current_gid = unsafe { libc::getgid() };
        let home = tempfile::tempdir().unwrap();

        daemon.configs.lock().insert(
            "alice".to_string(),
            AppConfig {
                name: "alice".to_string(),
                command: "/bin/sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "printf 'uid=%s home=%s user=%s\\n' \"$(id -u)\" \"$HOME\" \"$USER\""
                        .to_string(),
                ],
                uid: Some(current_uid),
                gid: Some(current_gid),
                oneshot: true,
                ..Default::default()
            },
        );

        let (child_end, mut parent_end) = std::os::unix::net::UnixStream::pair().unwrap();
        let request = Request::StartTerminal {
            name: "alice".to_string(),
            home: home.path().to_string_lossy().into_owned(),
            uid: current_uid,
            gid: Some(current_gid),
            pty: false,
            env: HashMap::from([
                (
                    "HOME".to_string(),
                    home.path().to_string_lossy().into_owned(),
                ),
                ("USER".to_string(), "alice".to_string()),
            ]),
            context: None,
            command: None,
            fd_count: None,
        };

        let response = daemon
            .handle_request_with_fd(request, OwnedFd::from(child_end), 0, 0)
            .await;
        assert!(response.success, "{:?}", response.error);
        let pid = response
            .data
            .as_ref()
            .and_then(|data| data.get("pid"))
            .and_then(serde_json::Value::as_u64)
            .expect("terminal response includes pid") as u32;
        assert!(
            tracked.lock().contains(&pid),
            "terminal pid {pid} should be tracked for SIGCHLD reaping"
        );

        let mut output = String::new();
        parent_end.read_to_string(&mut output).unwrap();
        assert!(output.contains(&format!("uid={}", current_uid)), "{output}");
        assert!(
            output.contains(&format!("home={}", home.path().display())),
            "{output}"
        );
        assert!(output.contains("user=alice"), "{output}");
    }

    #[tokio::test]
    async fn test_start_terminal_maps_three_stdio_fds() {
        let cfg = DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test.sock".to_string(),
        };
        let daemon = Daemon::new(cfg);
        let current_uid = unsafe { libc::getuid() };
        let current_gid = unsafe { libc::getgid() };
        let home = tempfile::tempdir().unwrap();

        daemon.configs.lock().insert(
            "alice".to_string(),
            AppConfig {
                name: "alice".to_string(),
                command: "/bin/sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "printf 'out\\n'; printf 'err\\n' >&2".to_string(),
                ],
                uid: Some(current_uid),
                gid: Some(current_gid),
                oneshot: true,
                ..Default::default()
            },
        );

        let (stdin_child, stdin_parent) = std::os::unix::net::UnixStream::pair().unwrap();
        let (stdout_child, mut stdout_parent) = std::os::unix::net::UnixStream::pair().unwrap();
        let (stderr_child, mut stderr_parent) = std::os::unix::net::UnixStream::pair().unwrap();
        let request = Request::StartTerminal {
            name: "alice".to_string(),
            home: home.path().to_string_lossy().into_owned(),
            uid: current_uid,
            gid: Some(current_gid),
            pty: false,
            env: HashMap::new(),
            context: None,
            command: None,
            fd_count: Some(3),
        };

        let response = daemon
            .handle_request_with_fds(
                request,
                vec![
                    OwnedFd::from(stdin_child),
                    OwnedFd::from(stdout_child),
                    OwnedFd::from(stderr_child),
                ],
                0,
                0,
            )
            .await;
        assert!(response.success, "{:?}", response.error);
        drop(stdin_parent);

        let mut stdout = String::new();
        let mut stderr = String::new();
        stdout_parent.read_to_string(&mut stdout).unwrap();
        stderr_parent.read_to_string(&mut stderr).unwrap();

        assert_eq!(stdout, "out\n");
        assert_eq!(stderr, "err\n");
    }

    #[tokio::test]
    async fn test_start_terminal_rejects_uid_mismatch_for_non_root_peer() {
        let cfg = DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test.sock".to_string(),
        };
        let daemon = Daemon::new(cfg);
        let current_uid = unsafe { libc::getuid() };
        let current_gid = unsafe { libc::getgid() };
        let home = tempfile::tempdir().unwrap();

        let (child_end, _parent_end) = std::os::unix::net::UnixStream::pair().unwrap();
        // Request a uid different from the peer's (current_uid).
        let requested_uid = if current_uid == 0 {
            // root peer is allowed to spawn as any uid; nothing to test here.
            return;
        } else if privileged_uids().contains(&current_uid) {
            // Privileged mesh-init peers, such as the default system uid 1000,
            // are also allowed to spawn as another uid.
            return;
        } else {
            current_uid.saturating_add(1)
        };
        let request = Request::StartTerminal {
            name: "dynamic-user".to_string(),
            home: home.path().to_string_lossy().into_owned(),
            uid: requested_uid,
            gid: Some(current_gid.saturating_add(1)),
            env: HashMap::new(),
            pty: false,
            context: None,
            command: None,
            fd_count: None,
        };

        // Pass peer_uid = current_uid (the actual non-root user).
        let response = daemon
            .handle_request_with_fd(request, OwnedFd::from(child_end), current_uid, current_gid)
            .await;
        assert!(
            !response.success,
            "non-root peer must not be able to spawn as a different uid; got success: {:?}",
            response.data
        );
        assert!(
            response
                .error
                .as_deref()
                .is_some_and(|e| e.contains("permission denied")),
            "expected permission-denied error, got: {:?}",
            response.error
        );
    }

    #[tokio::test]
    async fn test_register_namespace_stores_netns_fd() {
        let cfg = DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test.sock".to_string(),
        };
        let daemon = Daemon::new(cfg);
        let current_uid = unsafe { libc::getuid() };
        let mut proc = ManagedProcess::new(AppConfig {
            name: "net-svc".to_string(),
            command: "/bin/sleep".to_string(),
            args: vec!["60".to_string()],
            uid: Some(current_uid),
            ..Default::default()
        });
        proc.state = ServiceState::Running;
        proc.target_state = ServiceState::Running;
        proc.pid = Some(1234);
        daemon.services.lock().insert("net-svc".to_string(), proc);

        let (child_end, _parent_end) = std::os::unix::net::UnixStream::pair().unwrap();
        let response = daemon
            .handle_request_with_fd(
                Request::RegisterNamespace {
                    name: "net-svc".to_string(),
                    kind: NamespaceKind::Net,
                    target_pid: None,
                },
                OwnedFd::from(child_end),
                current_uid,
                unsafe { libc::getgid() },
            )
            .await;

        assert!(response.success, "{:?}", response.error);
        let status = daemon
            .services
            .lock()
            .get("net-svc")
            .expect("service")
            .status();
        assert!(status.netns_registered);
    }

    #[tokio::test]
    async fn test_register_namespace_rejects_unknown_service() {
        let cfg = DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test.sock".to_string(),
        };
        let daemon = Daemon::new(cfg);
        let current_uid = unsafe { libc::getuid() };
        let (child_end, _parent_end) = std::os::unix::net::UnixStream::pair().unwrap();

        let response = daemon
            .handle_request_with_fd(
                Request::RegisterNamespace {
                    name: "missing".to_string(),
                    kind: NamespaceKind::Net,
                    target_pid: None,
                },
                OwnedFd::from(child_end),
                current_uid,
                unsafe { libc::getgid() },
            )
            .await;

        assert!(!response.success);
        assert!(
            response
                .error
                .as_deref()
                .is_some_and(|e| e.contains("not found")),
            "expected not-found error, got: {:?}",
            response.error
        );
    }

    #[tokio::test]
    async fn test_privileged_uids_default_includes_root_system_sshd_and_mesh() {
        let _guard = ENV_MUTEX.lock();
        // Ensure no override env var leaks from another test.
        unsafe { std::env::remove_var("MESH_INIT_PRIVILEGED_UIDS") };
        let uids = privileged_uids();
        assert!(uids.contains(&0), "root must be privileged");
        assert!(uids.contains(&1000), "system (1000) must be privileged");
        assert!(
            uids.contains(&103),
            "default sshd uid (103) must be privileged"
        );
        assert!(
            uids.contains(&150),
            "default ssh-mesh uid (150) must be privileged"
        );
    }

    static ENV_MUTEX: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[tokio::test]
    async fn test_privileged_uids_env_override() {
        let _guard = ENV_MUTEX.lock();
        unsafe { std::env::set_var("MESH_INIT_PRIVILEGED_UIDS", "0,42") };
        let uids = privileged_uids();
        unsafe { std::env::remove_var("MESH_INIT_PRIVILEGED_UIDS") };
        assert_eq!(uids, vec![0, 42]);
    }

    #[tokio::test]
    async fn test_check_impersonation_allows_privileged_for_any_target() {
        let _guard = ENV_MUTEX.lock();
        // A privileged UID (1000) may target any UID.
        assert!(check_impersonation(1000, 1000, 0, None, "svc").is_ok());
        assert!(check_impersonation(1000, 1000, 9999, Some(9999), "svc").is_ok());
    }

    #[tokio::test]
    async fn test_check_impersonation_rejects_unprivileged_mismatch() {
        // A non-privileged UID may only target itself.
        assert!(check_impersonation(5000, 5000, 5000, None, "svc").is_ok());
        assert!(check_impersonation(5000, 5000, 0, None, "svc").is_err());
        assert!(check_impersonation(5000, 5000, 5000, Some(6000), "svc").is_err());
        assert!(check_impersonation(5000, 6000, 5000, Some(6000), "svc").is_ok());
    }

    #[test]
    fn restart_delay_jitter_keeps_one_second_delay_exact() {
        assert_eq!(restart_delay_with_jitter("svc-a", 1), 1);
    }

    #[test]
    fn restart_delay_jitter_is_bounded_and_deterministic() {
        let first = restart_delay_with_jitter("svc-a", 100);
        let second = restart_delay_with_jitter("svc-a", 100);
        assert_eq!(first, second);
        assert!((100..=110).contains(&first));
    }

    #[tokio::test]
    async fn test_oneshot_restart_behavior() {
        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-oneshot.sock".to_string(),
        });
        
        let mut config = AppConfig::default();
        config.name = "oneshot-svc".to_string();
        config.oneshot = true;
        config.restart = RestartPolicy::No;
        
        // 1. Exit with 0, Restart=No
        {
            let mut proc = ManagedProcess::new(config.clone());
            proc.state = ServiceState::Running;
            proc.target_state = ServiceState::Running;
            proc.pid = Some(9999);
            daemon.services.lock().insert("oneshot-svc".to_string(), proc);
            daemon.configs.lock().insert("oneshot-svc".to_string(), config.clone());

            daemon.handle_child_exit(9999, 0);

            let services = daemon.services.lock();
            let proc = services.get("oneshot-svc").unwrap();
            assert_eq!(proc.target_state, ServiceState::Stopped);
            assert_eq!(proc.state, ServiceState::Stopped);
            assert!(proc.pid.is_none());
        }

        // 2. Exit with 1, Restart=No
        {
            let mut proc = ManagedProcess::new(config.clone());
            proc.state = ServiceState::Running;
            proc.target_state = ServiceState::Running;
            proc.pid = Some(9998);
            daemon.services.lock().insert("oneshot-svc".to_string(), proc);

            daemon.handle_child_exit(9998, 1);

            let services = daemon.services.lock();
            let proc = services.get("oneshot-svc").unwrap();
            assert_eq!(proc.target_state, ServiceState::Stopped);
        }

        // 3. Exit with 1, Restart=OnFailure
        {
            let mut config_fail = config.clone();
            config_fail.restart = RestartPolicy::OnFailure;
            let mut proc = ManagedProcess::new(config_fail.clone());
            proc.state = ServiceState::Running;
            proc.target_state = ServiceState::Running;
            proc.pid = Some(9997);
            daemon.services.lock().insert("oneshot-svc".to_string(), proc);
            daemon.configs.lock().insert("oneshot-svc".to_string(), config_fail);

            daemon.handle_child_exit(9997, 1);

            let services = daemon.services.lock();
            let proc = services.get("oneshot-svc").unwrap();
            // Should restart! So target_state is still Running
            assert_eq!(proc.target_state, ServiceState::Running);
        }
    }

    #[tokio::test]
    async fn test_restart_sec_backoff_behavior() {
        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-restart-sec.sock".to_string(),
        });

        let mut config = AppConfig::default();
        config.name = "restart-sec-svc".to_string();
        config.restart = RestartPolicy::Always;
        config.restart_sec = 5; // 5 seconds restart delay

        // consecutive_failures should accumulate and use exponential backoff starting at 5s
        let mut proc = ManagedProcess::new(config.clone());
        proc.state = ServiceState::Running;
        proc.target_state = ServiceState::Running;
        proc.pid = Some(9999);
        daemon.services.lock().insert("restart-sec-svc".to_string(), proc);
        daemon.configs.lock().insert("restart-sec-svc".to_string(), config.clone());

        // First crash (ran for < 10s)
        daemon.handle_child_exit(9999, 1);
        {
            let services = daemon.services.lock();
            let proc = services.get("restart-sec-svc").unwrap();
            assert_eq!(proc.consecutive_failures, 1);
            let delay_dur = proc.next_restart_at.unwrap().duration_since(std::time::Instant::now());
            assert!(delay_dur >= std::time::Duration::from_millis(4500) && delay_dur <= std::time::Duration::from_millis(6500));
        }

        // Simulate restarting (updating state/pid, keep consecutive_failures=1)
        {
            let mut services = daemon.services.lock();
            let proc = services.get_mut("restart-sec-svc").unwrap();
            proc.state = ServiceState::Running;
            proc.pid = Some(9998);
            proc.started_at = Some(std::time::Instant::now());
        }

        // Second crash (ran for < 10s)
        daemon.handle_child_exit(9998, 1);
        {
            let services = daemon.services.lock();
            let proc = services.get("restart-sec-svc").unwrap();
            assert_eq!(proc.consecutive_failures, 2);
            let delay_dur = proc.next_restart_at.unwrap().duration_since(std::time::Instant::now());
            assert!(delay_dur >= std::time::Duration::from_millis(9500) && delay_dur <= std::time::Duration::from_millis(11500));
        }

        // Simulate restarting, running for > 10s (successful run)
        {
            let mut services = daemon.services.lock();
            let proc = services.get_mut("restart-sec-svc").unwrap();
            proc.state = ServiceState::Running;
            proc.pid = Some(9997);
            proc.started_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(12));
        }

        // Third crash (after running successfully for > 10s)
        daemon.handle_child_exit(9997, 1);
        {
            let services = daemon.services.lock();
            let proc = services.get("restart-sec-svc").unwrap();
            // consecutive_failures should be reset to 1
            assert_eq!(proc.consecutive_failures, 1);
            let delay_dur = proc.next_restart_at.unwrap().duration_since(std::time::Instant::now());
            assert!(delay_dur >= std::time::Duration::from_millis(4500) && delay_dur <= std::time::Duration::from_millis(6500));
        }
    }

    #[tokio::test]
    async fn test_watchdog_timeout_behavior() {
        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-watchdog.sock".to_string(),
        });

        let mut config = AppConfig::default();
        config.name = "watchdog-svc".to_string();
        config.watchdog_sec = Some(2); // 2 seconds watchdog
        config.watchdog_match = Some("active".to_string());

        let mut proc = ManagedProcess::new(config.clone());
        proc.state = ServiceState::Running;
        proc.target_state = ServiceState::Running;
        proc.pid = Some(9999);
        proc.started_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(3)); // already past startup grace period
        proc.last_watchdog_ping = Some(std::time::Instant::now() - std::time::Duration::from_secs(3)); // watchdog expired!

        daemon.services.lock().insert("watchdog-svc".to_string(), proc);

        // Run check_restarts. This should detect the watchdog timeout and kill the process.
        daemon.check_restarts();

        // In check_restarts, we kill via process::send_signal. Since PID 9999 doesn't exist, it won't crash the test.
        // Let's verify that last_watchdog_ping hasn't changed, but let's check that if we update last_watchdog_ping, check_restarts doesn't kill it.
        {
            let mut services = daemon.services.lock();
            let proc = services.get_mut("watchdog-svc").unwrap();
            proc.last_watchdog_ping = Some(std::time::Instant::now());
        }
        // This time it shouldn't trigger watchdog (last_watchdog_ping is recent).
        daemon.check_restarts();
    }

    #[tokio::test]
    async fn test_idle_termination_behavior() {
        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-idle.sock".to_string(),
        });

        let mut config = AppConfig::default();
        config.name = "idle-svc".to_string();
        config.idle_termination_sec = Some(2);

        let mut proc = ManagedProcess::new(config.clone());
        proc.state = ServiceState::Running;
        proc.target_state = ServiceState::Running;
        proc.pid = Some(9999);
        proc.last_active = Some(0);
        proc.last_sess = Some(0);
        proc.last_stderr_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(3)); // no stderr for 3 seconds

        daemon.services.lock().insert("idle-svc".to_string(), proc);

        // First check_restarts tick: sets idle_since
        daemon.check_restarts();

        {
            let services = daemon.services.lock();
            let proc = services.get("idle-svc").unwrap();
            assert!(proc.idle_since.is_some());
        }

        // Simulate time passing (move idle_since back in time)
        {
            let mut services = daemon.services.lock();
            let proc = services.get_mut("idle-svc").unwrap();
            proc.idle_since = Some(std::time::Instant::now() - std::time::Duration::from_secs(3));
        }

        // Second check_restarts tick: triggers idle termination
        daemon.check_restarts();

        {
            let services = daemon.services.lock();
            let proc = services.get("idle-svc").unwrap();
            assert_eq!(proc.target_state, ServiceState::Stopped);
        }
    }
}
