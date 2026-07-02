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

use crate::config::{self, AppConfig};
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
/// 103) is included, since sshd must spawn shells as other users.
///
/// Root (UID 0) is always privileged. The full list can be overridden with the
/// `MESH_INIT_PRIVILEGED_UIDS` env var (comma-separated).
const DEFAULT_SYSTEM_UID: u32 = 1000;

/// Resolve the set of UIDs permitted to act as a different user (i.e. spawn
/// or control a process whose UID differs from the peer's).
///
/// If `MESH_INIT_PRIVILEGED_UIDS` is set, it fully overrides the default list.
/// Otherwise the list is `[0, 1000]` plus the sshd UID from
/// [`mesh::auth::trusted_sshd_uid`] (if `Some`).
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
    let mut uids = vec![0, DEFAULT_SYSTEM_UID];
    if let Some(sshd) = mesh::auth::trusted_sshd_uid() {
        if !uids.contains(&sshd) {
            uids.push(sshd);
        }
    }
    uids
}

/// Check whether `peer_uid` is permitted to act as `target_uid`/`target_gid`.
///
/// Privileged UIDs (see [`privileged_uids`]) may target any UID. A non-
/// privileged peer may only target its own UID. Returns `Ok(())` if allowed,
/// or `Err(Response)` with a permission-denied response.
fn check_impersonation(
    peer_uid: u32,
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
        && g != peer_uid
    {
        return Err(Response::err(format!(
            "permission denied: peer UID {} may not operate on service '{}' (GID {})",
            peer_uid, name, g
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
    tracked_child_pids: Mutex<Option<Arc<parking_lot::Mutex<std::collections::HashSet<u32>>>>>,
}

struct TerminalSession {
    name: String,
    pid: u32,
    pty_fd: Option<OwnedFd>,
}

fn apply_activation_context_env(config: &mut AppConfig, context: Option<ActivationContext>) {
    if let Some(context) = context {
        config.env.extend(context.to_env());
    }
}

impl Daemon {
    /// Create a new daemon instance.
    pub fn new(config: DaemonConfig) -> Arc<Self> {
        let services = Arc::new(Mutex::new(HashMap::new()));
        let resource_manager = Some(ResourceManager::new(services.clone()));
        let observer = Arc::new(ProcessObserver::new().expect("create mesh-init process observer"));

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
        })
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

        // 1b. Load systemd .socket units and merge activation entries into
        //     matching service configs. Skip if no .service with that name exists.
        for dir in &dirs {
            let socket_units = crate::socket_unit::load_socket_units(dir);
            for (service_name, act_configs) in socket_units {
                let mut configs = self.configs.lock();
                if let Some(cfg) = configs.get_mut(&service_name) {
                    let count = act_configs.len();
                    cfg.activation.extend(act_configs);
                    info!(
                        "Merged {} activation(s) from socket unit into service '{}'",
                        count, service_name
                    );
                } else {
                    error!(
                        "Socket unit for '{}' has no matching service '{}' (expected '{}.service'). Skipping.",
                        service_name, service_name, service_name
                    );
                }
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
                // default.service only provides defaults for execution mode
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
            } else if let Err(e) = self.start_service_internal(&cfg.name) {
                error!("Failed to auto-start service '{}': {}", cfg.name, e);
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
    pub async fn handle_request(&self, request: Request, peer_uid: u32) -> Response {
        match request {
            Request::Start {
                name,
                args,
                env,
                context,
            } => self.handle_start(&name, args, env, context, peer_uid),
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
            Request::Stop { name, signal } => self.handle_stop(&name, signal, peer_uid).await,
            Request::Freeze { name } => self.handle_freeze(&name, peer_uid),
            Request::Unfreeze { name } => self.handle_unfreeze(&name, peer_uid),
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
            } => self.handle_observer_cgroup_high(path, percentage, interval),
            Request::CgroupProcs { path } => self.handle_observer_cgroup_procs(&path),
            Request::MoveProcess { pid, cgroup_name } => {
                self.handle_observer_move_process(pid, cgroup_name)
            }
            Request::ClearRefs { pid, value } => self.handle_observer_clear_refs(pid, &value),
            Request::FreezeProcess { pid, freeze } => {
                self.handle_observer_freeze_process(pid, freeze)
            }
            Request::FreezeCgroup { path, freeze } => {
                self.handle_observer_freeze_cgroup(&path, freeze)
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

    /// Handle a control request that carries one Unix file descriptor.
    pub async fn handle_request_with_fd(
        &self,
        request: Request,
        fd: OwnedFd,
        peer_uid: u32,
    ) -> Response {
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
                &name, &home, uid, gid, pty, env, context, command, fd, peer_uid,
            ),
            Request::RegisterNamespace {
                name,
                kind,
                target_pid,
            } => self.handle_register_namespace(&name, kind, target_pid, fd, peer_uid),
            _ => Response::err("request does not accept a passed file descriptor"),
        }
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
        extra_env: HashMap<String, String>,
        context: Option<ActivationContext>,
        peer_uid: u32,
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
                if let Err(resp) =
                    check_impersonation(peer_uid, cfg.uid.unwrap_or(peer_uid), cfg.gid, name)
                {
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
                    match config::load_app_config(std::path::Path::new(path)) {
                        Ok(new_cfg) => {
                            debug!("Reloaded config for {}", name);
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
                let base_dir =
                    std::env::var("USER_INIT").unwrap_or_else(|_| "/data/mesh".to_string());
                let app_dir = std::path::Path::new(&base_dir).join(name);
                let service_path = app_dir.join("init.service");

                if service_path.exists() {
                    match config::load_app_config(&service_path) {
                        Ok(mut new_cfg) => {
                            // Enforce UID/GID from directory, ignoring whatever the file says
                            if let Ok(metadata) = std::fs::metadata(&app_dir) {
                                use std::os::unix::fs::MetadataExt;
                                new_cfg.uid = Some(metadata.uid());
                                new_cfg.gid = Some(metadata.gid());
                                new_cfg.user = None;
                                new_cfg.group = None;
                            }

                            info!("Loaded on-demand user config for '{}'", name);
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

        // Merge extra args and env
        config.args.extend(extra_args);
        config.env.extend(extra_env);
        apply_activation_context_env(&mut config, context);

        // Check resource availability
        if let Some(ref rm) = self.resource_manager
            && !rm.can_start(&config)
        {
            return Response::err("insufficient resources to start service");
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
        extra_env: HashMap<String, String>,
        context: Option<ActivationContext>,
        command: Option<String>,
        fd: OwnedFd,
        peer_uid: u32,
    ) -> Response {
        if let Err(reason) = crate::config::validate_cgroup_name(name) {
            return Response::err(format!("invalid service name: {reason}"));
        }
        // Authorization: a non-privileged peer may only spawn processes as
        // itself. Privileged UIDs (root, system, sshd — see `privileged_uids`)
        // may target any UID. This prevents privilege escalation where an
        // authorized non-privileged peer requests uid=0.
        if let Err(resp) = check_impersonation(peer_uid, uid, gid, name) {
            return resp;
        }
        let home_path = std::path::Path::new(home);
        if !home_path.is_dir() {
            return Response::err(format!("home directory '{}' does not exist", home));
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
        if let Err(resp) =
            check_impersonation(peer_uid, config.uid.unwrap_or(peer_uid), config.gid, name)
        {
            return resp;
        }

        let cg =
            crate::cgroup::create_cgroup(name).unwrap_or_else(|_| "/sys/fs/cgroup".to_string());
        let retained_pty = if pty {
            match fd.try_clone() {
                Ok(fd) => Some(fd),
                Err(e) => return Response::err(format!("failed to retain PTY fd: {}", e)),
            }
        } else {
            None
        };
        let activation_fd = if pty {
            process::ActivationFd::Pty(fd)
        } else {
            process::ActivationFd::Stdio(fd)
        };

        match process::spawn_process(&config, &cg, Some(activation_fd)) {
            Ok(pid) => {
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

        let pid = {
            let terminals = self.terminal_sessions.lock();
            let Some(session) = terminals.get(terminal_id) else {
                return Response::err(format!("terminal session '{}' not found", terminal_id));
            };
            session.pid
        };

        match process::send_signal(pid, signal) {
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

    async fn handle_stop(&self, name: &str, signal: Option<i32>, peer_uid: u32) -> Response {
        if let Err(reason) = crate::config::validate_cgroup_name(name) {
            return Response::err(format!("invalid service name: {reason}"));
        }
        let (pid, network_pid) = {
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
                    if let Err(resp) = check_impersonation(peer_uid, svc_uid, svc_gid, name) {
                        return resp;
                    }
                    proc.state = ServiceState::Stopping;
                    proc.target_state = ServiceState::Stopped;
                    proc.netns_fd = None;
                    proc.userns_fd = None;
                    proc.namespace_pid = None;
                    proc.mesh_tun_attached = false;
                    (proc.pid, proc.network_pid)
                }
                Some(_) => return Response::err(format!("service '{}' is not running", name)),
                None => return Response::err(format!("service '{}' not found", name)),
            }
        };

        if let Some(network_pid) = network_pid {
            let _ = process::send_signal(network_pid, libc::SIGTERM);
        }
        if let Some(pid) = pid
            && let Err(e) = process::stop_process(pid, signal).await
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

        info!("Stopped service '{}'", name);
        Response::ok()
    }

    fn handle_freeze(&self, name: &str, peer_uid: u32) -> Response {
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
        if let Err(resp) = check_impersonation(peer_uid, svc_uid, svc_gid, name) {
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

    fn handle_unfreeze(&self, name: &str, peer_uid: u32) -> Response {
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
        if let Err(resp) = check_impersonation(peer_uid, svc_uid, svc_gid, name) {
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
    ) -> Response {
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

    fn handle_observer_move_process(&self, pid: u32, cgroup_name: Option<String>) -> Response {
        match self.observer.move_process_to_cgroup(pid, cgroup_name) {
            Ok(()) => Response::ok(),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_observer_clear_refs(&self, pid: u32, value: &str) -> Response {
        match self.observer.clear_refs(pid, value) {
            Ok(()) => Response::ok_with_data(serde_json::json!({
                "message": format!("cleared refs for process {pid} with value {value}")
            })),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_observer_freeze_process(&self, pid: u32, freeze: bool) -> Response {
        match self.observer.freeze_process(pid, freeze) {
            Ok(()) => Response::ok(),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_observer_freeze_cgroup(&self, path: &str, freeze: bool) -> Response {
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

        for new_cfg in loaded_configs {
            let name = new_cfg.name.clone();
            let is_changed = match configs.get(&name) {
                Some(old_cfg) => *old_cfg != new_cfg,
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

        Response::ok_with_data(serde_json::json!({"reloaded": true, "changed": changed}))
    }

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    fn handle_child_exit(&self, pid: u32, exit_code: i32) {
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
                if let Some(network_pid) = proc.network_pid.take() {
                    let _ = process::send_signal(network_pid, libc::SIGTERM);
                }

                if proc.config.oneshot {
                    proc.target_state = ServiceState::Stopped;
                }

                if !intentionally_stopped && proc.target_state == ServiceState::Running {
                    // crashed or was killed for restart!
                    proc.consecutive_failures += 1;

                    if let Some(max_retries) = proc.config.backoff.max_retries {
                        if proc.consecutive_failures > max_retries {
                            warn!(
                                "Service '{}' crashed {} times, exceeding max_retries ({}). Marking as stopped.",
                                name, proc.consecutive_failures, max_retries
                            );
                            proc.target_state = ServiceState::Stopped;
                            return;
                        }
                    }

                    let initial = proc.config.backoff.initial_secs;
                    let mut backoff_secs = match proc.config.backoff.policy {
                        crate::config::BackoffPolicy::Linear => {
                            initial.saturating_mul(proc.consecutive_failures as u64)
                        }
                        crate::config::BackoffPolicy::Exponential => {
                            let multiplier = 1_u64
                                .checked_shl(proc.consecutive_failures - 1)
                                .unwrap_or(u64::MAX);
                            initial.saturating_mul(multiplier)
                        }
                    };

                    if proc.config.backoff.max_retries.is_none() {
                        backoff_secs = backoff_secs.min(24 * 3600);
                    }

                    let restart_delay_secs = restart_delay_with_jitter(name, backoff_secs);

                    info!(
                        "Service '{}' crashed. Scheduling restart #{} in {}s",
                        name, proc.consecutive_failures, restart_delay_secs
                    );

                    proc.next_restart_at = Some(
                        std::time::Instant::now()
                            + std::time::Duration::from_secs(restart_delay_secs),
                    );
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
                        let backoff_secs = (1 << (proc.consecutive_failures - 1)).min(60);
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
        let pid = match process::spawn_process(&config, cg, passed_fd) {
            Ok(p) => p,
            Err(e) => {
                // Spawn failed: mark the service Stopped so it can be restarted.
                let mut services = self.services.lock();
                if let Some(proc) = services.get_mut(&name) {
                    proc.state = ServiceState::Stopped;
                    proc.pid = None;
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
                proc.config = config;
            }
        }
        info!("Service '{}' started with PID {}", name, pid);

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
                let _ = process::stop_process(pid, None).await;
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

    #[test]
    fn test_daemon_config_loading() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("sleep.service");
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
            .handle_request_with_fd(request, OwnedFd::from(child_end), 0)
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
            .handle_request_with_fd(request, OwnedFd::from(child_end), current_uid)
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
    async fn test_privileged_uids_default_includes_root_system_and_sshd() {
        let uids = privileged_uids();
        assert!(uids.contains(&0), "root must be privileged");
        assert!(uids.contains(&1000), "system (1000) must be privileged");
        assert!(
            uids.contains(&103),
            "default sshd uid (103) must be privileged"
        );
    }

    #[tokio::test]
    async fn test_privileged_uids_env_override() {
        // SAFETY: this test runs single-threaded under the TEST_MUTEX.
        unsafe { std::env::set_var("MESH_INIT_PRIVILEGED_UIDS", "0,42") };
        let uids = privileged_uids();
        unsafe { std::env::remove_var("MESH_INIT_PRIVILEGED_UIDS") };
        assert_eq!(uids, vec![0, 42]);
    }

    #[tokio::test]
    async fn test_check_impersonation_allows_privileged_for_any_target() {
        // A privileged UID (1000) may target any UID.
        assert!(check_impersonation(1000, 0, None, "svc").is_ok());
        assert!(check_impersonation(1000, 9999, Some(9999), "svc").is_ok());
    }

    #[tokio::test]
    async fn test_check_impersonation_rejects_unprivileged_mismatch() {
        // A non-privileged UID may only target itself.
        assert!(check_impersonation(5000, 5000, None, "svc").is_ok());
        assert!(check_impersonation(5000, 0, None, "svc").is_err());
        assert!(check_impersonation(5000, 5000, Some(6000), "svc").is_err());
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
}
