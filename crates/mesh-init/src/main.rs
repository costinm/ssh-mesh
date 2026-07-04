//! mesh-init — minimal init/supervisor daemon with mesh and resource awareness.
//!
//! When run without a subcommand, starts the daemon. With a subcommand,
//! connects to a running daemon via UDS and sends a control request.

use anyhow::Result;
use clap::Parser;
use std::collections::HashMap;
use tracing::{error, info};

use mesh_init::daemon::{Daemon, DaemonConfig};
use mesh_init::protocol::{Request, Response};

#[derive(Parser, Debug)]
#[clap(name = "mesh-init", version = "0.1.0", trailing_var_arg = true)]
struct Args {
    /// Command to execute immediately. If omitted, runs as a daemon.
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let (_log_buffer, _trace_guard) = mesh::local_trace::init("mesh-init");

    let args = Args::parse();
    let socket_path = get_socket_path();
    let config_dirs = get_config_dirs();

    if let Some(request) = control_request(&args.command)? {
        let response = mesh_init::server::send_request(&socket_path, &request).await?;
        print_response(response)?;
        return Ok(());
    }

    let command = if args.command.is_empty() {
        None
    } else {
        Some(args.command)
    };

    run(config_dirs, socket_path, command).await
}

fn control_request(command: &[String]) -> Result<Option<Request>> {
    let Some(method) = command.first().map(String::as_str) else {
        return Ok(None);
    };

    let request = match method {
        "reload" => Request::Reload,
        "status" => Request::Status {
            name: command.get(1).cloned(),
        },
        "start" => {
            let Some(name) = command.get(1) else {
                anyhow::bail!("usage: mesh-init start SERVICE [ARGS...]");
            };
            Request::Start {
                name: name.clone(),
                args: command[2..].to_vec(),
                env: HashMap::new(),
                context: None,
            }
        }
        "stop" => {
            let Some(name) = command.get(1) else {
                anyhow::bail!("usage: mesh-init stop SERVICE [--signal SIGNAL]");
            };
            let mut signal = None;
            let mut i = 2;
            while i < command.len() {
                match command[i].as_str() {
                    "--signal" => {
                        let Some(value) = command.get(i + 1) else {
                            anyhow::bail!("missing value for --signal");
                        };
                        signal = Some(value.parse()?);
                        i += 2;
                    }
                    other => anyhow::bail!("unknown stop argument: {}", other),
                }
            }
            Request::Stop {
                name: name.clone(),
                signal,
            }
        }
        "shutdown" => Request::Shutdown,
        "freeze" => {
            let Some(name) = command.get(1) else {
                anyhow::bail!("usage: mesh-init freeze SERVICE");
            };
            Request::Freeze { name: name.clone() }
        }
        "unfreeze" => {
            let Some(name) = command.get(1) else {
                anyhow::bail!("usage: mesh-init unfreeze SERVICE");
            };
            Request::Unfreeze { name: name.clone() }
        }
        _ => return Ok(None),
    };

    Ok(Some(request))
}

fn print_response(response: Response) -> Result<()> {
    if response.success {
        if let Some(data) = response.data {
            println!("{}", serde_json::to_string_pretty(&data)?);
        } else {
            println!("OK");
        }
        Ok(())
    } else {
        eprintln!(
            "Error: {}",
            response.error.as_deref().unwrap_or("unknown error")
        );
        std::process::exit(1);
    }
}

/// Common startup: create daemon, start everything, optionally run a CLI command.
async fn run(
    config_dirs: Vec<String>,
    socket_path: String,
    command: Option<Vec<String>>,
) -> Result<()> {
    // Collect systemd socket activation file descriptors before the daemon
    // creates its own listeners. This must happen before start_background_tasks.
    mesh_init::activation::collect_systemd_fds();

    let config = DaemonConfig {
        config_dirs,
        socket_path: socket_path.clone(),
    };

    info!(
        "Starting mesh-init (PID {}, UID {}, mode={})",
        std::process::id(),
        unsafe { libc::getuid() },
        if command.is_some() { "exec" } else { "daemon" }
    );

    let daemon = Daemon::new(config);

    if let Some(command) = command {
        // Execution mode: run only the requested command. Do not autostart
        // configured services or bind the daemon control socket; doing so can
        // steal the real daemon's socket when mesh-init is used as a shell.
        {
            let dirs: Vec<&str> = daemon
                .config
                .config_dirs
                .iter()
                .map(|s| s.as_str())
                .collect();
            let loaded_configs = mesh_init::config::load_system_configs(&dirs);
            let mut configs = daemon.configs.lock();
            for cfg in loaded_configs {
                configs.insert(cfg.name.clone(), cfg.clone());
            }
        }
        daemon.start_child_manager();

        // Run init-* services first
        let init_configs = {
            let configs = daemon.configs.lock();
            let mut inits: Vec<_> = configs
                .values()
                .filter(|c| c.name.starts_with("init-"))
                .cloned()
                .collect();
            inits.sort_by_key(|c| c.priority);
            inits
        };

        for init_cfg in init_configs {
            info!("Running init setup service '{}'", init_cfg.name);
            let name = init_cfg.name.clone();
            match daemon.start_service_with_config(init_cfg, None) {
                Ok(_) => {
                    wait_for_service_exit(&daemon, &name).await;
                }
                Err(e) => {
                    error!("Failed to start init setup service '{}': {}", name, e);
                }
            }
        }

        let app_name = "cmd";
        let cmd = command[0].clone();
        let args = command[1..].to_vec();

        // Apply defaults from default.toml if present. Execution mode is used
        // by VM/container init scripts as a small "run this command under the
        // default service policy" entrypoint, so hardening/identity/resource
        // fields from default.toml should apply to the command too.
        let default_cfg = daemon.configs.lock().get("default").cloned();

        let mut cfg = default_cfg.unwrap_or_default();
        cfg.name = app_name.to_string();
        cfg.command = cmd;
        cfg.args = args;
        cfg.exec_start_pre.clear();
        cfg.exec_start_post.clear();
        cfg.exec_stop.clear();
        cfg.exec_reload.clear();
        cfg.restart = mesh_init::config::RestartPolicy::No;
        cfg.oneshot = true;
        cfg.activation.clear();
        cfg.source_path = None;

        info!("Executing command: {} {:?}", cfg.command, cfg.args);
        let _pid = daemon.start_service_with_config(cfg, None)?;

        // Wait for the main command to end
        wait_for_service_exit(&daemon, app_name).await;

        daemon.shutdown().await;
    } else {
        // Start all background tasks: load configs, start init-* services,
        // start regular services/activation listeners, resource manager, child reaper.
        daemon.start_background_tasks();

        // Start job scheduler
        let jobs_dir = mesh::paths::AppPaths::for_app("system")
            .etc
            .join("mesh-init/jobs")
            .to_string_lossy()
            .into_owned();
        let executor =
            std::sync::Arc::new(mesh::jobs::executor::MeshInitExecutor::new(socket_path));
        let scheduler =
            std::sync::Arc::new(mesh::jobs::scheduler::JobScheduler::new(jobs_dir, executor));

        let sched_clone = scheduler.clone();
        tokio::spawn(async move {
            if let Err(e) = sched_clone.check_jobs().await {
                tracing::error!("JobScheduler failed to check jobs: {}", e);
            }
        });

        // Daemon mode: run the control server in the foreground (blocks until shutdown).
        let server = mesh_init::server::ControlServer::new(
            daemon.config.socket_path.clone(),
            daemon.clone(),
        );
        server.run().await?;
    }

    Ok(())
}

/// Wait until a service transitions to Stopped state.
async fn wait_for_service_exit(daemon: &std::sync::Arc<Daemon>, name: &str) {
    let mut rx = daemon.service_exit_tx.subscribe();

    // Check initial state first to avoid missing an exit that happened before we subscribed
    {
        let services = daemon.services.lock();
        if let Some(proc) = services.get(name) {
            if proc.state == mesh_init::protocol::ServiceState::Stopped && proc.pid.is_none() {
                return;
            }
        } else {
            return;
        }
    }

    while let Ok(exited_name) = rx.recv().await {
        if exited_name == name {
            let services = daemon.services.lock();
            if let Some(proc) = services.get(name) {
                if proc.state == mesh_init::protocol::ServiceState::Stopped && proc.pid.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
    }
}

fn get_config_dirs() -> Vec<String> {
    mesh_init::config::core_config_dirs()
        .into_iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect()
}

fn get_socket_path() -> String {
    if let Ok(path) = std::env::var("MESH_INIT_SOCK") {
        return path;
    }
    if let Ok(dir) = std::env::var("MESH_INIT_RUN") {
        return std::path::PathBuf::from(dir)
            .join("control.sock")
            .to_string_lossy()
            .into_owned();
    }
    mesh::paths::AppPaths::for_app("mesh-init")
        .mesh_socket()
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_is_control_request() {
        let args = vec!["reload".to_string()];
        assert!(matches!(
            control_request(&args).unwrap(),
            Some(Request::Reload)
        ));
    }

    #[test]
    fn unknown_command_remains_exec_mode() {
        let args = vec!["echo".to_string(), "hi".to_string()];
        assert!(control_request(&args).unwrap().is_none());
    }

    #[test]
    fn default_paths_use_system_app_home() {
        assert_eq!(
            get_config_dirs(),
            mesh_init::config::core_config_dirs()
                .into_iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            get_socket_path(),
            mesh::paths::AppPaths::for_app("mesh-init")
                .mesh_socket()
                .to_string_lossy()
        );
    }
}
