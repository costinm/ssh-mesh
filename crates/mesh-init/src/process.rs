//! Process lifecycle management for mesh-init services.
//!
//! Handles fork/exec with privilege drop (setuid/setgid), signal-based
//! stop/freeze/unfreeze, and PID 1 zombie reaping.

use std::time::Instant;

use tracing::{debug, error, info, warn};

use crate::config::AppConfig;
use crate::protocol::ServiceState;

// ============================================================================
// Error Types
// ============================================================================

/// Errors from process operations.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Process not found: PID {0}")]
    NotFound(u32),

    #[error("Spawn failed: {0}")]
    SpawnFailed(String),

    #[error("Signal error: {0}")]
    SignalError(String),

    #[error("Cgroup error: {0}")]
    Cgroup(#[from] crate::cgroup::CgroupError),
}

// ============================================================================
// Managed Process
// ============================================================================

/// A process managed by the daemon.
#[derive(Debug)]
pub struct ManagedProcess {
    /// The service configuration.
    pub config: AppConfig,
    /// Current lifecycle state.
    pub state: ServiceState,
    /// The requested state (whether the daemon wants it to be running or stopped).
    pub target_state: ServiceState,
    /// PID of the running process (None if stopped).
    pub pid: Option<u32>,
    /// When the process was last started.
    pub started_at: Option<Instant>,
    /// Number of times this service has been restarted.
    pub restarts: u32,
    /// Number of consecutive crashes for backoff calculation.
    pub consecutive_failures: u32,
    /// Time when the service can be restarted next.
    pub next_restart_at: Option<Instant>,
    /// Cgroup path for this service.
    pub cgroup_path: Option<String>,
}

impl ManagedProcess {
    /// Create a new managed process from config.
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            state: ServiceState::Stopped,
            target_state: ServiceState::Stopped,
            pid: None,
            started_at: None,
            restarts: 0,
            consecutive_failures: 0,
            next_restart_at: None,
            cgroup_path: None,
        }
    }

    /// Get uptime in seconds, if running or frozen.
    pub fn uptime_secs(&self) -> Option<u64> {
        self.started_at.map(|t| t.elapsed().as_secs())
    }

    /// Convert to a status report.
    pub fn status(&self) -> crate::protocol::ServiceStatus {
        crate::protocol::ServiceStatus {
            name: self.config.name.clone(),
            state: self.state,
            pid: self.pid,
            uptime_secs: self.uptime_secs(),
            restarts: self.restarts,
            consecutive_failures: self.consecutive_failures,
            next_restart_in_secs: self.next_restart_at.map(|t| {
                let now = Instant::now();
                if t > now { (t - now).as_secs() } else { 0 }
            }),
            cgroup_path: self.cgroup_path.clone(),
        }
    }
}

// ============================================================================
// Process Operations
// ============================================================================

/// How an FD should be passed to an activated service.
pub enum ActivationFd {
    /// inetd-style (wait=false): accepted client socket → stdin/stdout/stderr.
    Stdio(std::os::fd::OwnedFd),
    /// Terminal-style activation: PTY slave → controlling terminal and stdio.
    Pty(std::os::fd::OwnedFd),
    /// xinetd-style (wait=true): listening socket → FD 3(+), LISTEN_FD env var.
    Listen(std::os::fd::OwnedFd),
}

/// Spawn a new process for a service.
///
/// Uses `std::process::Command` to fork and exec. Sets uid/gid if configured.
/// After spawn, moves the child into the service's cgroup and sets OOM score.
pub fn spawn_process(
    config: &AppConfig,
    cgroup_path: &str,
    passed_fd: Option<ActivationFd>,
) -> Result<u32, ProcessError> {
    info!(
        "Spawning service '{}': {} {:?}",
        config.name, config.command, config.args
    );

    let mut cmd = std::process::Command::new(&config.command);
    cmd.args(&config.args);

    // Set environment
    for (key, value) in &config.env {
        cmd.env(key, value);
    }

    // Set uid/gid if specified
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        if let Some(uid) = config.uid {
            cmd.uid(uid);
        }
        if let Some(gid) = config.gid {
            cmd.gid(gid);
        }
    }

    let mut _passed_fd_keepalive = None;

    match passed_fd {
        Some(ActivationFd::Stdio(fd)) => {
            // inetd-style: map client socket to stdin/stdout/stderr
            let stdout_fd = fd.try_clone().map_err(ProcessError::Io)?;
            let stderr_fd = fd.try_clone().map_err(ProcessError::Io)?;
            cmd.stdin(std::process::Stdio::from(fd));
            cmd.stdout(std::process::Stdio::from(stdout_fd));
            cmd.stderr(std::process::Stdio::from(stderr_fd));
        }
        Some(ActivationFd::Pty(fd)) => {
            use std::os::fd::AsRawFd;
            use std::os::unix::process::CommandExt;

            let raw_fd = fd.as_raw_fd();
            let stdin_fd = fd.try_clone().map_err(ProcessError::Io)?;
            let stdout_fd = fd.try_clone().map_err(ProcessError::Io)?;
            let stderr_fd = fd.try_clone().map_err(ProcessError::Io)?;
            cmd.stdin(std::process::Stdio::from(stdin_fd));
            cmd.stdout(std::process::Stdio::from(stdout_fd));
            cmd.stderr(std::process::Stdio::from(stderr_fd));
            _passed_fd_keepalive = Some(fd);

            // SAFETY: pre_exec runs in the child after fork and before exec.
            // It only calls async-signal-safe libc operations.
            unsafe {
                cmd.pre_exec(move || {
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::ioctl(raw_fd, libc::TIOCSCTTY, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(raw_fd, 0) < 0
                        || libc::dup2(raw_fd, 1) < 0
                        || libc::dup2(raw_fd, 2) < 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        Some(ActivationFd::Listen(fd)) => {
            // xinetd-style: pass as extra FD and set env var.
            // The FD will be inherited as-is; we use pre_exec to clear CLOEXEC.
            use std::os::fd::AsRawFd;
            let raw = fd.as_raw_fd();
            // Tell the child where to find it
            cmd.env("LISTEN_FD", raw.to_string());
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                // SAFETY: only calls async-signal-safe libc functions
                unsafe {
                    let fd_to_keep = raw;
                    cmd.pre_exec(move || {
                        // Clear CLOEXEC so the FD survives exec
                        let flags = libc::fcntl(fd_to_keep, libc::F_GETFD);
                        if flags >= 0 {
                            libc::fcntl(fd_to_keep, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                        }
                        Ok(())
                    });
                }
            }
            // Keep the OwnedFd alive so it isn't closed before exec. Hold it
            // until after `cmd.spawn()` returns; the child inherits the FD
            // (CLOEXEC was cleared in pre_exec), and the parent's copy is
            // then closed when `_passed_fd_keepalive` drops at end of scope.
            // Previously this used `mem::forget`, which leaked the parent's
            // copy permanently (one FD per wait=true activation).
            _passed_fd_keepalive = Some(fd);
        }
        None => {}
    }

    let child = cmd.spawn().map_err(|e| {
        error!("Failed to spawn '{}': {}", config.name, e);
        ProcessError::SpawnFailed(format!("{}: {}", config.command, e))
    })?;

    let pid = child.id();
    info!("Spawned service '{}' with PID {}", config.name, pid);

    // Move into cgroup
    if let Err(e) = crate::cgroup::move_to_cgroup(pid, cgroup_path) {
        warn!(
            "Failed to move PID {} to cgroup {}: {}",
            pid, cgroup_path, e
        );
    }

    // Set OOM score
    if let Some(oom) = config.oom_score_adjust
        && let Err(e) = crate::cgroup::set_oom_score(pid, oom)
    {
        warn!("Failed to set oom_score_adj for PID {}: {}", pid, e);
    }

    Ok(pid)
}

/// Send a signal to a process.
pub fn send_signal(pid: u32, signal: i32) -> Result<(), ProcessError> {
    let res = unsafe { libc::kill(pid as i32, signal) };
    if res == 0 {
        debug!("Sent signal {} to PID {}", signal, pid);
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            Err(ProcessError::NotFound(pid))
        } else {
            Err(ProcessError::SignalError(format!(
                "kill({}, {}): {}",
                pid, signal, err
            )))
        }
    }
}

/// Stop a process. Sends the given signal (default SIGTERM), waits briefly,
/// then sends SIGKILL if still alive.
///
/// Liveness is checked with `waitpid(pid, WNOHANG)` rather than `kill(pid, 0)`
/// to avoid the PID-recycle hazard: if the child already exited and its PID was
/// recycled by the kernel, `kill(pid, 0)` would succeed (alive) and we would
/// SIGKILL an unrelated process. `waitpid(pid)` returns `ECHILD` for a PID
/// that is not our child (already reaped or recycled), so we never signal a
/// stranger.
pub async fn stop_process(pid: u32, signal: Option<i32>) -> Result<(), ProcessError> {
    let sig = signal.unwrap_or(libc::SIGTERM);
    info!("Stopping PID {} with signal {}", pid, sig);

    send_signal(pid, sig)?;

    // Give it a moment to exit
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Check if the child has exited using waitpid on the specific PID.
    // Returns:
    //   0   — child still running
    //   pid — child exited, status reaped
    //  -1   — ECHILD: not our child (already reaped by the global reaper, or
    //         PID was recycled). Either way, do NOT escalate to SIGKILL.
    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
    if ret == 0 {
        warn!(
            "PID {} still alive after signal {}, sending SIGKILL",
            pid, sig
        );
        let _ = send_signal(pid, libc::SIGKILL);
        // Reap the killed child if we can (best-effort; the global reaper may
        // race us, which is harmless).
        let mut s: libc::c_int = 0;
        let _ = unsafe { libc::waitpid(pid as libc::pid_t, &mut s, libc::WNOHANG) };
    } else {
        debug!(
            "PID {} exited after signal {} (waitpid ret={})",
            pid, sig, ret
        );
    }

    Ok(())
}

/// Freeze a process using SIGSTOP. If a cgroup path is provided,
/// uses cgroup.freeze instead for a cleaner freeze.
pub fn freeze_process(pid: u32, cgroup_path: Option<&str>) -> Result<(), ProcessError> {
    if let Some(cg) = cgroup_path {
        crate::cgroup::freeze_cgroup(cg, true)?;
        info!("Froze service via cgroup {}", cg);
    } else {
        send_signal(pid, libc::SIGSTOP)?;
        info!("Froze PID {} with SIGSTOP", pid);
    }
    Ok(())
}

/// Unfreeze a process using SIGCONT or cgroup.freeze=0.
pub fn unfreeze_process(pid: u32, cgroup_path: Option<&str>) -> Result<(), ProcessError> {
    if let Some(cg) = cgroup_path {
        crate::cgroup::freeze_cgroup(cg, false)?;
        info!("Unfroze service via cgroup {}", cg);
    } else {
        send_signal(pid, libc::SIGCONT)?;
        info!("Unfroze PID {} with SIGCONT", pid);
    }
    Ok(())
}

/// Start the background task to listen for child process exits.
/// When a child exits, its PID and exit code are sent through the channel.
///
/// When running as PID 1 (or with `MESH_INIT_REAP_ALL=1`), uses
/// `waitpid(-1, WNOHANG)` to reap any child. When not PID 1, this is dangerous
/// because `waitpid(-1)` reaps *every* child of the process, stealing exit
/// notifications from any other `Child::wait()` caller in the same process
/// (e.g. libraries that spawn helper processes). In that case we instead reap
/// only PIDs that the caller registers via the returned `tracked_pids` set.
pub fn start_child_reaper(
    tx: tokio::sync::mpsc::Sender<(u32, i32)>,
) -> std::sync::Arc<parking_lot::Mutex<std::collections::HashSet<u32>>> {
    let tracked_pids =
        std::sync::Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new()));
    let reap_all = is_pid1()
        || std::env::var("MESH_INIT_REAP_ALL")
            .map(|v| v.trim().eq_ignore_ascii_case("1") || v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    let tracked = tracked_pids.clone();

    tokio::spawn(async move {
        let mut sigchld = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
        {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to register SIGCHLD handler: {}", e);
                return;
            }
        };

        loop {
            sigchld.recv().await;

            if reap_all {
                // PID 1: reap all children.
                loop {
                    let mut status = 0;
                    let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                    if pid <= 0 {
                        break;
                    }
                    let exit_code = exit_code_from_status(status);
                    debug!("Reaped child PID {} with exit code {}", pid, exit_code);
                    let _ = tx.send((pid as u32, exit_code)).await;
                }
            } else {
                // Not PID 1: reap only tracked PIDs to avoid stealing reaps
                // from other Child::wait() callers in this process.
                let pids: Vec<u32> = tracked.lock().iter().copied().collect();
                for pid in pids {
                    let mut status = 0;
                    let ret =
                        unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
                    if ret == pid as libc::pid_t {
                        let exit_code = exit_code_from_status(status);
                        debug!(
                            "Reaped tracked child PID {} with exit code {}",
                            pid, exit_code
                        );
                        tracked.lock().remove(&pid);
                        let _ = tx.send((pid, exit_code)).await;
                    } else if ret > 0 {
                        // reaped but pid mismatch (shouldn't happen for specific pid)
                        tracked.lock().remove(&pid);
                    }
                    // ret == 0: still running; ret < 0: already reaped or not ours
                    if ret < 0 {
                        tracked.lock().remove(&pid);
                    }
                }
            }
        }
    });

    tracked_pids
}

fn exit_code_from_status(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        -libc::WTERMSIG(status)
    } else {
        -1
    }
}

/// Check if the current process is PID 1.
pub fn is_pid1() -> bool {
    std::process::id() == 1
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Read;
    use std::os::fd::{FromRawFd, OwnedFd};

    fn test_config(name: &str) -> AppConfig {
        AppConfig {
            name: name.to_string(),
            command: "/bin/true".to_string(),
            args: vec![],
            uid: None,
            gid: None,
            user: None,
            group: None,
            env: HashMap::new(),
            priority: 500,
            oneshot: false,
            oom_score_adjust: None,
            resources: crate::config::ResolvedResourceLimits::default(),
            activation: vec![],
            source_path: None,
            ..Default::default()
        }
    }

    #[test]
    fn test_pty_activation_gives_child_terminal() {
        let mut config = test_config("pty-test");
        config.command = "/bin/sh".to_string();
        config.args = vec![
            "-c".to_string(),
            "if test -t 0; then echo tty-ok; else echo no-tty; fi".to_string(),
        ];
        config.oneshot = true;

        let mut master = 0;
        let mut slave = 0;
        let open_result = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(
            open_result,
            0,
            "openpty failed: {}",
            std::io::Error::last_os_error()
        );

        let mut master = unsafe { std::fs::File::from_raw_fd(master) };
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        let pid = spawn_process(&config, "/sys/fs/cgroup", Some(ActivationFd::Pty(slave))).unwrap();

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
        assert_eq!(waited, pid as i32);
        assert!(libc::WIFEXITED(status), "status={status}");
        assert_eq!(libc::WEXITSTATUS(status), 0, "status={status}");

        let mut output = String::new();
        let _ = master.read_to_string(&mut output);
        assert!(output.contains("tty-ok"), "{output}");
    }

    #[test]
    fn test_managed_process_state_transitions() {
        let mut proc = ManagedProcess::new(test_config("test"));
        assert_eq!(proc.state, ServiceState::Stopped);
        assert!(proc.pid.is_none());

        // Simulate starting
        proc.state = ServiceState::Starting;
        assert_eq!(proc.state, ServiceState::Starting);

        proc.state = ServiceState::Running;
        proc.pid = Some(1234);
        proc.started_at = Some(Instant::now());
        assert_eq!(proc.state, ServiceState::Running);
        assert_eq!(proc.pid, Some(1234));

        // Simulate freeze
        proc.state = ServiceState::Frozen;
        assert_eq!(proc.state, ServiceState::Frozen);

        // Simulate unfreeze
        proc.state = ServiceState::Running;
        assert_eq!(proc.state, ServiceState::Running);

        // Simulate stop
        proc.state = ServiceState::Stopping;
        assert_eq!(proc.state, ServiceState::Stopping);

        proc.state = ServiceState::Stopped;
        proc.pid = None;
        assert_eq!(proc.state, ServiceState::Stopped);
    }

    #[test]
    fn test_managed_process_status() {
        let mut proc = ManagedProcess::new(test_config("my-svc"));
        proc.state = ServiceState::Running;
        proc.pid = Some(42);
        proc.restarts = 3;

        let status = proc.status();
        assert_eq!(status.name, "my-svc");
        assert_eq!(status.state, ServiceState::Running);
        assert_eq!(status.pid, Some(42));
        assert_eq!(status.restarts, 3);
    }

    #[test]
    fn test_is_pid1() {
        // We're not PID 1 in tests
        assert!(!is_pid1());
    }
}
