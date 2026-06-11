//! mesh-init — minimal init/supervisor daemon with mesh and resource awareness.
//!
//! When run without a subcommand, starts the daemon. With a subcommand,
//! connects to a running daemon via UDS and sends a control request.

use anyhow::Result;
use clap::Parser;
use std::fs::OpenOptions;
use tracing::info;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

use mesh_init::daemon::{Daemon, DaemonConfig};

#[derive(Parser, Debug)]
#[clap(name = "mesh-init", version = "0.1.0", trailing_var_arg = true)]
struct Args {
    /// Command to execute immediately. If omitted, runs as a daemon.
    command: Vec<String>,
}

// ============================================================================
// Main
// ============================================================================

fn init_telemetry() {
    let filter = EnvFilter::from_default_env();
    let log_path = std::env::var("MESH_LOG_FILE").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.run/mesh-init/mesh-init.log", home)
    });

    if let Some(parent) = std::path::Path::new(&log_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Ok(file) = OpenOptions::new().create(true).append(true).open(&log_path) {
        let out_layer = tracing_subscriber::fmt::layer()
            .compact()
            .with_writer(move || file.try_clone().expect("clone mesh-init log file"));
        Registry::default().with(filter).with(out_layer).init();
    } else {
        Registry::default().with(filter).init();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_telemetry();

    let args = Args::parse();
    let socket_path = get_socket_path();
    let config_dir = get_config_dir();

    let command = if args.command.is_empty() {
        None
    } else {
        Some(args.command)
    };

    run(config_dir, socket_path, command).await
}

/// Common startup: create daemon, start everything, optionally run a CLI command.
async fn run(config_dir: String, socket_path: String, command: Option<Vec<String>>) -> Result<()> {
    let config = DaemonConfig {
        config_dirs: vec![config_dir],
        socket_path: socket_path.clone(),
    };

    info!(
        "Starting mesh-init (PID {}, UID {}, mode={})",
        std::process::id(),
        unsafe { libc::getuid() },
        if command.is_some() { "exec" } else { "daemon" }
    );

    let daemon = Daemon::new(config);

    // Start all background tasks: load configs, start init-* services,
    // start regular services/activation listeners, resource manager, child reaper.
    daemon.start_background_tasks();

    // Start job scheduler
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let jobs_dir = format!("{}/.config/mesh-init/jobs", home);
    let executor = std::sync::Arc::new(mesh::jobs::executor::MeshInitExecutor::new(socket_path));
    let scheduler =
        std::sync::Arc::new(mesh::jobs::scheduler::JobScheduler::new(jobs_dir, executor));

    let sched_clone = scheduler.clone();
    tokio::spawn(async move {
        if let Err(e) = sched_clone.check_jobs().await {
            tracing::error!("JobScheduler failed to check jobs: {}", e);
        }
    });

    if let Some(command) = command {
        // Execution mode: start the CLI command, run control server in background, exit when done.
        let server = mesh_init::server::ControlServer::new(
            daemon.config.socket_path.clone(),
            daemon.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                tracing::error!("Control server error: {}", e);
            }
        });

        let app_name = "cmd";
        let cmd = command[0].clone();
        let args = command[1..].to_vec();

        // Apply defaults from default.toml if present
        let default_cfg = daemon.configs.lock().get("default").cloned();

        let cfg = mesh_init::config::AppConfig {
            name: app_name.to_string(),
            command: cmd,
            args,
            uid: default_cfg.as_ref().and_then(|d| d.uid),
            gid: default_cfg.as_ref().and_then(|d| d.gid),
            user: default_cfg.as_ref().and_then(|d| d.user.clone()),
            group: default_cfg.as_ref().and_then(|d| d.group.clone()),
            env: default_cfg
                .as_ref()
                .map(|d| d.env.clone())
                .unwrap_or_default(),
            priority: 0,
            oneshot: true,
            oom_score_adjust: default_cfg.as_ref().and_then(|d| d.oom_score_adjust),
            resources: default_cfg
                .as_ref()
                .map(|d| d.resources.clone())
                .unwrap_or_default(),
            activation: vec![],
            source_path: None,
            ..Default::default()
        };

        info!("Executing command: {} {:?}", cfg.command, cfg.args);
        let _pid = daemon.start_service_with_config(cfg, None)?;

        // Wait for the main command to end
        wait_for_service_exit(&daemon, app_name).await;

        daemon.shutdown().await;
    } else {
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
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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

fn get_config_dir() -> String {
    if let Ok(dir) = std::env::var("MESH_INIT_DIR") {
        return dir;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    format!("{}/.config/mesh-init", home)
}

fn get_socket_path() -> String {
    let run_dir = if let Ok(dir) = std::env::var("MESH_INIT_RUN") {
        dir
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        format!("{}/.run/mesh-init", home)
    };
    format!("{}/control.sock", run_dir)
}
