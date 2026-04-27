//! Socket activation for mesh-init services.
//!
//! Handles listening on TCP ports and UDS sockets on behalf of services.
//! Uses the xinetd model: configurable inetd-style per-connection invocation or 
//! xinetd-style pass-listening-FD behavior.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use tracing::{debug, error, info};
use tokio::io::unix::AsyncFd;

use crate::config::AppConfig;
use crate::daemon::Daemon;
use crate::process::ActivationFd;
use crate::protocol::ServiceState;

/// Start activation listeners for a given service.
pub fn start_listeners(daemon: Arc<Daemon>, config: &AppConfig) {
    for act in &config.activation {
        if let Some(port) = act.port {
            let daemon_clone = daemon.clone();
            let name = config.name.clone();
            let wait = act.wait;
            tokio::spawn(async move {
                run_tcp_listener(port, name, wait, daemon_clone).await;
            });
        }
        if let Some(ref path) = act.socket {
            let daemon_clone = daemon.clone();
            let name = config.name.clone();
            let path_clone = path.clone();
            let wait = act.wait;
            tokio::spawn(async move {
                run_uds_listener(path_clone, name, wait, daemon_clone).await;
            });
        }
    }
}

async fn run_tcp_listener(port: u16, service_name: String, wait: bool, daemon: Arc<Daemon>) {
    let addr = format!("0.0.0.0:{}", port);
    info!("Starting TCP activation listener for '{}' on {}", service_name, addr);
    
    let listener = match std::net::TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind TCP activation port {} for '{}': {}", port, service_name, e);
            return;
        }
    };
    if let Err(e) = listener.set_nonblocking(true) {
        error!("Failed to set TCP listener non-blocking: {}", e);
        return;
    }
    
    // Convert to OwnedFd to pass around generically
    let fd = listener.into();
    handle_listener(fd, service_name, wait, daemon).await;
}

async fn run_uds_listener(path: String, service_name: String, wait: bool, daemon: Arc<Daemon>) {
    info!("Starting UDS activation listener for '{}' on {}", service_name, path);
    let _ = std::fs::remove_file(&path);
    
    let listener = match std::os::unix::net::UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind UDS activation socket {} for '{}': {}", path, service_name, e);
            return;
        }
    };
    if let Err(e) = listener.set_nonblocking(true) {
        error!("Failed to set UDS listener non-blocking: {}", e);
        return;
    }
    
    let fd = listener.into();
    handle_listener(fd, service_name, wait, daemon).await;
}

async fn handle_listener(listener_fd: OwnedFd, service_name: String, wait: bool, daemon: Arc<Daemon>) {
    let async_fd = match AsyncFd::new(listener_fd) {
        Ok(afd) => afd,
        Err(e) => {
            error!("Failed to register listener FD with tokio: {}", e);
            return;
        }
    };

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
            // wait=true mode (xinetd style)
            // Pass the listening socket directly. Service calls accept().
            // Do not clear readiness here because we want the child to accept it.
            // But we must wait for the child to exit before polling again.

            let config_opt = daemon.configs.lock().get(&service_name).cloned();
            if let Some(config) = config_opt {
                let passed_fd = async_fd.get_ref().try_clone().ok()
                    .map(ActivationFd::Listen);
                if let Err(e) = daemon.start_service_with_config(config, passed_fd) {
                    error!("Failed to activate service {}: {}", service_name, e);
                } else {
                    // Wait until service exits
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        let services = daemon.services.lock();
                        if let Some(proc) = services.get(&service_name) {
                            if proc.state == ServiceState::Stopped && proc.pid.is_none() {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
            
            // Re-arm readiness (since child accepted the connection hopefully)
            guard.clear_ready();
        } else {
            // wait=false mode (inetd style)
            // We accept the connection and pass the client socket.
            // Since we're working with raw FDs, we'll use libc::accept or tokio wrapper.
            let raw_fd = async_fd.get_ref().as_raw_fd();
            let client_fd = unsafe { libc::accept(raw_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
            
            if client_fd < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                error!("Accept error on {}: {}", service_name, err);
                // Try again after delay
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }

            // Successfully accepted
            guard.retain_ready(); // there might be more connections
            let client_owned = unsafe { OwnedFd::from_raw_fd(client_fd) };

            let config_opt = daemon.configs.lock().get(&service_name).cloned();
            if let Some(config) = config_opt {
                let cg = crate::cgroup::create_cgroup(&service_name)
                    .unwrap_or_else(|_| "/sys/fs/cgroup".to_string());
                
                // Spawn the process directly, passing the client socket.
                // We do NOT use start_service_with_config because there could be multiple instances.
                match crate::process::spawn_process(&config, &cg, Some(ActivationFd::Stdio(client_owned))) {
                    Ok(pid) => {
                        debug!("Spawned activated instance (wait=false) PID {}", pid);
                    }
                    Err(e) => {
                        error!("Failed to spawn activated instance for {}: {}", service_name, e);
                    }
                }
            }
        }
    }
}
