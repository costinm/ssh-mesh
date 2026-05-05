//! mesh-init — minimal init/supervisor daemon with mesh and resource awareness.
//!
//! When run without a subcommand, starts the daemon. With a subcommand,
//! connects to a running daemon via UDS and sends a control request.

use anyhow::Result;
use clap::Parser;
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
    let out_layer = tracing_subscriber::fmt::layer().compact();

    Registry::default()
        .with(EnvFilter::from_default_env())
        .with(out_layer)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_telemetry();

    let args = Args::parse();
    let socket_path = get_socket_path();
    let config_dir = get_config_dir();

    if args.command.is_empty() {
        run_daemon(config_dir, socket_path).await?
    } else {
        run_and_exit(config_dir, socket_path, args.command).await?
    }

    Ok(())
}

/// Run the daemon.
async fn run_daemon(config_dir: String, socket_path: String) -> Result<()> {
    let config = DaemonConfig {
        config_dirs: vec![config_dir],
        socket_path: socket_path.clone(),
    };

    info!(
        "Starting mesh-init daemon (PID {}, UID {})",
        std::process::id(),
        unsafe { libc::getuid() }
    );

    let daemon = Daemon::new(config);

    // Start job scheduler
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let jobs_dir = format!("{}/.config/mesh/jobs", home);
    let executor = std::sync::Arc::new(mesh::jobs::executor::MeshInitExecutor::new(socket_path));
    let scheduler =
        std::sync::Arc::new(mesh::jobs::scheduler::JobScheduler::new(jobs_dir, executor));

    let sched_clone = scheduler.clone();
    tokio::spawn(async move {
        if let Err(e) = sched_clone.check_jobs().await {
            tracing::error!("JobScheduler failed to check jobs: {}", e);
        }
    });

    daemon.run().await?;
    Ok(())
}

/// Run as a supervisor for a single command, then exit.
///
/// Loads configs from the config directory. If `default.toml` exists,
/// its settings (UID, GID, resources, environment) are applied to the
/// main command. Any `init-*` configs are executed first (sorted by priority).
async fn run_and_exit(config_dir: String, socket_path: String, command: Vec<String>) -> Result<()> {
    let daemon_config = DaemonConfig {
        config_dirs: vec![config_dir.clone()],
        socket_path,
    };

    let daemon = Daemon::new(daemon_config);

    // Load all configs from the config directory
    let loaded_configs = mesh_init::config::load_system_configs(&[&config_dir]);

    // Store them in the daemon's config registry
    {
        let mut configs = daemon.configs.lock();
        for cfg in &loaded_configs {
            configs.insert(cfg.name.clone(), cfg.clone());
        }
    }

    // Start resource manager
    daemon.start_background_tasks_minimal();

    // Separate init-* configs from the rest
    let mut init_configs: Vec<&mesh_init::config::AppConfig> = loaded_configs
        .iter()
        .filter(|c| c.name.starts_with("init-"))
        .collect();
    init_configs.sort_by_key(|c| c.priority);

    // Run init-* services first and wait for oneshots to complete
    for cfg in &init_configs {
        info!("Running init service '{}'", cfg.name);
        match daemon.start_service_with_config((*cfg).clone(), None) {
            Ok(_pid) => {
                if cfg.oneshot {
                    // Wait for oneshot init services to finish
                    wait_for_service_exit(&daemon, &cfg.name).await;
                }
            }
            Err(e) => {
                tracing::error!("Failed to start init service '{}': {}", cfg.name, e);
            }
        }
    }

    // Start activation listeners for non-init services
    for cfg in &loaded_configs {
        if !cfg.name.starts_with("init-") && cfg.name != "default" && !cfg.activation.is_empty() {
            mesh_init::activation::start_listeners(daemon.clone(), cfg);
        }
    }

    // Build the main command config, applying defaults from default.toml if present
    let cmd = command[0].clone();
    let args = command[1..].to_vec();
    let app_name = "cmd";

    let default_cfg = loaded_configs.iter().find(|c| c.name == "default");

    let cfg = mesh_init::config::AppConfig {
        name: app_name.to_string(),
        command: cmd,
        args,
        uid: default_cfg.and_then(|d| d.uid),
        gid: default_cfg.and_then(|d| d.gid),
        user: default_cfg.and_then(|d| d.user.clone()),
        group: default_cfg.and_then(|d| d.group.clone()),
        env: default_cfg.map(|d| d.env.clone()).unwrap_or_default(),
        priority: 0,
        oneshot: true,
        oom_score_adjust: default_cfg.and_then(|d| d.oom_score_adjust),
        resources: default_cfg.map(|d| d.resources.clone()).unwrap_or_default(),
        activation: vec![],
        source_path: None,
    };

    info!("Executing command: {} {:?}", cfg.command, cfg.args);
    let _pid = daemon.start_service_with_config(cfg, None)?;

    // Wait for the main command to end
    wait_for_service_exit(&daemon, app_name).await;

    daemon.shutdown().await;
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
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    format!("{}/.config/mesh-init", home)
}

fn get_socket_path() -> String {
    let run_dir = if let Ok(dir) = std::env::var("MESH_INIT_RUN") {
        dir
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.run/mesh-init", home)
    };
    format!("{}/control.sock", run_dir)
}
