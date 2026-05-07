//! Main daemon loop for mesh-init.
//!
//! Manages service lifecycle: loads configs, starts system services,
//! handles control requests, manages signal handling and zombie reaping.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use parking_lot::Mutex;
use tracing::{debug, error, info, warn};

use crate::config::{self, AppConfig};
use crate::process::{self, ManagedProcess};
use crate::protocol::{Request, Response, ServiceState, ServiceStatus};
use crate::resource::ResourceManager;

// ============================================================================
// Daemon
// ============================================================================

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
    resource_manager: Option<ResourceManager>,
}

impl Daemon {
    /// Create a new daemon instance.
    pub fn new(config: DaemonConfig) -> Arc<Self> {
        let services = Arc::new(Mutex::new(HashMap::new()));
        let resource_manager = Some(ResourceManager::new(services.clone()));

        Arc::new(Self {
            config,
            services,
            configs: Arc::new(Mutex::new(HashMap::new())),
            resource_manager,
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

        // 2. Start resource manager
        if let Some(ref rm) = self.resource_manager {
            rm.start();
        }

        // 3. Auto-start system services or start activation listeners.
        // init-* services run first (sorted by priority), then the rest.
        let mut init_configs: Vec<&AppConfig> = Vec::new();
        let mut other_configs: Vec<&AppConfig> = Vec::new();
        for cfg in &loaded_configs {
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
            } else if let Err(e) = self.start_service_internal(&cfg.name) {
                error!("Failed to auto-start service '{}': {}", cfg.name, e);
            }
        }

        // 4. Spawn child process manager (zombie reaper + restarts)
        self.start_child_manager();
    }


    /// Spawn the child process manager (zombie reaper + restart loop).
    fn start_child_manager(self: &Arc<Self>) {
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        process::start_child_reaper(tx);

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
    pub async fn handle_request(&self, request: Request) -> Response {
        match request {
            Request::Start { name, args, env } => self.handle_start(&name, args, env),
            Request::Stop { name, signal } => self.handle_stop(&name, signal).await,
            Request::Freeze { name } => self.handle_freeze(&name),
            Request::Unfreeze { name } => self.handle_unfreeze(&name),
            Request::Status { name } => self.handle_status(name.as_deref()),
            Request::Shutdown => self.handle_shutdown().await,
            Request::Reload => self.handle_reload(),
            // Job scheduling requests are handled by the JobScheduler, not the main Daemon service manager
            Request::ScheduleJob { .. } |
            Request::CancelJob { .. } |
            Request::EnqueueWork { .. } |
            Request::ListJobs |
            Request::JobFinished { .. } |
            Request::Event { .. } => {
                Response::err("Job scheduling requests are not handled directly by the daemon socket yet.")
            }
        }
    }

    // ========================================================================
    // Request Handlers
    // ========================================================================

    fn handle_start(
        &self,
        name: &str,
        extra_args: Vec<String>,
        extra_env: HashMap<String, String>,
    ) -> Response {
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
                let base_dir = std::env::var("USER_INIT")
                    .unwrap_or_else(|_| "/data/mesh".to_string());
                let app_dir = std::path::Path::new(&base_dir).join(name);
                let toml_path = app_dir.join("init.toml");

                if toml_path.exists() {
                    match config::load_app_config(&toml_path) {
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
                            return Response::err(format!("failed to load user config for '{}': {}", name, e));
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

    async fn handle_stop(&self, name: &str, signal: Option<i32>) -> Response {
        let pid = {
            let mut services = self.services.lock();
            match services.get_mut(name) {
                Some(proc)
                    if proc.state == ServiceState::Running
                        || proc.state == ServiceState::Frozen =>
                {
                    proc.state = ServiceState::Stopping;
                    proc.target_state = ServiceState::Stopped;
                    proc.pid
                }
                Some(_) => return Response::err(format!("service '{}' is not running", name)),
                None => return Response::err(format!("service '{}' not found", name)),
            }
        };

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
            }
        }

        info!("Stopped service '{}'", name);
        Response::ok()
    }

    fn handle_freeze(&self, name: &str) -> Response {
        let mut services = self.services.lock();
        let proc = match services.get_mut(name) {
            Some(p) if p.state == ServiceState::Running => p,
            Some(_) => return Response::err(format!("service '{}' is not running", name)),
            None => return Response::err(format!("service '{}' not found", name)),
        };

        if let Some(pid) = proc.pid {
            if let Err(e) = process::freeze_process(pid, proc.cgroup_path.as_deref()) {
                return Response::err(e.to_string());
            }
            proc.state = ServiceState::Frozen;
            info!("Froze service '{}'", name);
        }

        Response::ok()
    }

    fn handle_unfreeze(&self, name: &str) -> Response {
        let mut services = self.services.lock();
        let proc = match services.get_mut(name) {
            Some(p) if p.state == ServiceState::Frozen => p,
            Some(_) => return Response::err(format!("service '{}' is not frozen", name)),
            None => return Response::err(format!("service '{}' not found", name)),
        };

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
        let mut services = self.services.lock();
        for (name, proc) in services.iter_mut() {
            if proc.pid == Some(pid) {
                let intentionally_stopped = proc.target_state == ServiceState::Stopped;
                info!(
                    "Service '{}' (PID {}) exited with code {}. Intentional: {}",
                    name, pid, exit_code, intentionally_stopped
                );

                proc.state = ServiceState::Stopped;
                proc.pid = None;

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
                            let multiplier = 1_u64.checked_shl(proc.consecutive_failures - 1).unwrap_or(u64::MAX);
                            initial.saturating_mul(multiplier)
                        }
                    };

                    if proc.config.backoff.max_retries.is_none() {
                        backoff_secs = backoff_secs.min(24 * 3600);
                    }

                    info!(
                        "Service '{}' crashed. Scheduling restart #{} in {}s",
                        name, proc.consecutive_failures, backoff_secs
                    );

                    proc.next_restart_at = Some(
                        std::time::Instant::now()
                            + std::time::Duration::from_secs(backoff_secs),
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
                        proc.next_restart_at = Some(
                            std::time::Instant::now()
                                + std::time::Duration::from_secs(backoff_secs as u64),
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
    pub fn start_service_with_config(&self, config: AppConfig, passed_fd: Option<crate::process::ActivationFd>) -> Result<u32> {
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

        // Spawn process
        let pid = process::spawn_process(&config, cg, passed_fd)?;

        // Register managed process. If it exists, update it, otherwise create new.
        let mut services = self.services.lock();
        if let Some(proc) = services.get_mut(&name) {
            proc.state = ServiceState::Running;
            proc.target_state = ServiceState::Running;
            proc.pid = Some(pid);
            proc.started_at = Some(std::time::Instant::now());
            proc.cgroup_path = cgroup_path;
            proc.config = config; // update config just in case
        } else {
            let mut proc = ManagedProcess::new(config);
            proc.state = ServiceState::Running;
            proc.target_state = ServiceState::Running;
            proc.pid = Some(pid);
            proc.started_at = Some(std::time::Instant::now());
            proc.cgroup_path = cgroup_path;
            services.insert(name.clone(), proc);
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_config_loading() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("sleep.toml");
        std::fs::write(
            &config_path,
            r#"
[service]
name = "sleep"
command = "/bin/sleep"
args = ["10"]
priority = 300
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
}
