use mesh_tun::control::{run_bwrap_info_server, run_control_server, BwrapInfoServerConfig};
use mesh_tun::flow::MeshPassthrough;
use mesh_tun::uds::{run_uds_server, UdsServerConfig, UdsStyle};
use mesh_tun::vhost_user::{spawn_vhost_user_net, VhostUserNetConfig};
use mesh_tun::{MeshTun, MeshTunConfig};
use std::env;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use tokio::net::UnixListener;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{reload, EnvFilter, Registry};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "bwrap" {
        return run_bwrap_command(&args[2..]);
    }

    let log_buffer = init_telemetry();

    // Resolve and bind trace listener UDS socket
    let trace_socket_str =
        env::var("MESH_TUN_TRACE_SOCKET").unwrap_or_else(|_| "trace.sock".to_string());

    let log_buffer_clone = log_buffer.clone();
    match resolve_and_bind_uds("mesh-tun", &trace_socket_str, "MESH_TUN_TRACE_FD", None) {
        Ok(trace_listener) => {
            tokio::spawn(async move {
                if let Err(error) = mesh::local_trace::start_uds_listener_from_listener(
                    trace_listener,
                    log_buffer_clone,
                )
                .await
                {
                    tracing::error!(%error, "UDS trace listener stopped");
                }
            });
        }
        Err(error) => {
            tracing::error!(%error, "Failed to bind UDS trace listener");
        }
    }

    let mode = env::var("MESH_TUN_MODE").unwrap_or_else(|_| {
        if env_truthy("MESH_TUN_REAL_TUN") {
            "tun".to_string()
        } else {
            "uds".to_string()
        }
    });

    let config = mesh_tun_config_from_env()?;
    let passthrough = Arc::new(MeshPassthrough::new(config.vm_id.clone()));

    match mode.as_str() {
        "tun" | "real-tun" => run_real_tun(config, passthrough).await,
        "uds" | "unix" | "unix-socket" => run_capture_sockets(config, passthrough).await,
        other => anyhow::bail!("unsupported MESH_TUN_MODE={other}; expected uds or tun"),
    }
}

fn run_bwrap_command(args: &[String]) -> Result<(), anyhow::Error> {
    let Some(command_separator) = args.iter().position(|arg| arg == "--") else {
        anyhow::bail!("usage: mesh-tun bwrap [bwrap-args...] -- [command...]");
    };

    let bwrap_socket =
        env::var("MESH_TUN_BWRAP_SOCKET").unwrap_or_else(|_| "/tmp/mesh-tun-bwrap.sock".into());
    let stream = std::os::unix::net::UnixStream::connect(&bwrap_socket)
        .map_err(|error| anyhow::anyhow!("connect {bwrap_socket}: {error}"))?;
    let info_fd = dup_fd(stream.as_raw_fd())?;
    let block_fd = dup_fd(stream.as_raw_fd())?;
    drop(stream);

    let mut bwrap_args = args[..command_separator].to_vec();
    let command = if command_separator + 1 == args.len() {
        vec![env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())]
    } else {
        args[command_separator + 1..].to_vec()
    };

    bwrap_args.extend([
        "--info-fd".to_string(),
        info_fd.to_string(),
        "--block-fd".to_string(),
        block_fd.to_string(),
        "--".to_string(),
    ]);
    bwrap_args.extend(command);

    let status = Command::new("bwrap").args(&bwrap_args).status();
    close_fd(info_fd);
    close_fd(block_fd);

    let status = status?;
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    if let Some(signal) = status.signal() {
        anyhow::bail!("bwrap terminated by signal {signal}");
    }
    anyhow::bail!("bwrap terminated without an exit code")
}

fn dup_fd(fd: i32) -> Result<i32, anyhow::Error> {
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(duplicated)
}

fn close_fd(fd: i32) {
    unsafe {
        libc::close(fd);
    }
}

async fn run_real_tun(
    config: MeshTunConfig,
    passthrough: Arc<MeshPassthrough>,
) -> Result<(), anyhow::Error> {
    let tun = MeshTun::new(config)?;
    let injector = tun
        .run(
            passthrough.clone(),
            passthrough.clone(),
            passthrough.clone(),
        )
        .await?;
    passthrough.set_injector(injector);
    std::future::pending::<()>().await;
    Ok(())
}

async fn run_capture_sockets(
    config: MeshTunConfig,
    passthrough: Arc<MeshPassthrough>,
) -> Result<(), anyhow::Error> {
    let run_dir = get_run_dir();
    let socket_path_str = env::var("MESH_TUN_SOCKET").unwrap_or_else(|_| "qemu.sock".to_string());

    let resolved_socket_path = if socket_path_str.starts_with('/') {
        PathBuf::from(&socket_path_str)
    } else if socket_path_str.starts_with('_') {
        PathBuf::from(&socket_path_str)
    } else {
        run_dir.join(&socket_path_str)
    };

    let capture_listener = resolve_and_bind_uds(
        "mesh-tun",
        &socket_path_str,
        "MESH_TUN_CAPTURE_FD",
        Some("LISTEN_FD"),
    )?;

    let style = UdsStyle::from_env_value(
        &env::var("MESH_TUN_UDS_STYLE").unwrap_or_else(|_| "qemu".to_string()),
    )?;

    let control_socket_str =
        env::var("MESH_TUN_CONTROL_SOCKET").unwrap_or_else(|_| "control.sock".to_string());

    let control_listener =
        resolve_and_bind_uds("mesh-tun", &control_socket_str, "MESH_TUN_CONTROL_FD", None)?;
    let bwrap_socket_str =
        env::var("MESH_TUN_BWRAP_SOCKET").unwrap_or_else(|_| "bwrap.sock".to_string());
    let bwrap_listener =
        resolve_and_bind_uds("mesh-tun", &bwrap_socket_str, "MESH_TUN_BWRAP_FD", None)?;

    let vhost_socket = env::var("MESH_TUN_VHOST_SOCKET")
        .ok()
        .map(PathBuf::from)
        .or_else(|| env_truthy("MESH_TUN_ENABLE_VHOST").then(|| run_dir.join("vhost.sock")));
    let tun = MeshTun::new(config)?;
    let (injector, tun_tx, mut stack_rx) = tun
        .run_with_channels(
            passthrough.clone(),
            passthrough.clone(),
            passthrough.clone(),
        )
        .await?;
    passthrough.set_injector(injector);

    let (fallback_tx, fallback_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(packet) = stack_rx.recv().await {
            if !mesh_tun::control::route_outgoing_packet(&packet) {
                let _ = fallback_tx.send(packet);
            }
        }
    });

    let control_tx = tun_tx.clone();
    tokio::spawn(async move {
        if let Err(error) = run_control_server(control_listener, control_tx).await {
            tracing::error!(%error, "mesh-tun control socket stopped");
        }
    });

    let bwrap_tx = tun_tx.clone();
    let pool = env::var("MESH_TUN_BWRAP_POOL").unwrap_or_else(|_| "10.5.0.0/24".to_string());
    let (network, prefix_len) = parse_ipv4_cidr(&pool)?;
    let bwrap_config = BwrapInfoServerConfig {
        if_name: env::var("MESH_TUN_BWRAP_IF").unwrap_or_else(|_| "tap0".to_string()),
        network,
        prefix_len,
        first_host: env::var("MESH_TUN_BWRAP_FIRST_HOST")
            .ok()
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(2),
        gateway: env::var("MESH_TUN_BWRAP_GW").unwrap_or_else(|_| "10.5.0.1".to_string()),
        vm_id: env::var("MESH_TUN_BWRAP_VM_ID").unwrap_or_else(|_| "bwrap".to_string()),
    };
    tokio::spawn(async move {
        if let Err(error) = run_bwrap_info_server(bwrap_listener, bwrap_config, bwrap_tx).await {
            tracing::error!(%error, "mesh-tun bwrap info socket stopped");
        }
    });

    if let Some(socket_path) = vhost_socket {
        let mut vhost_config =
            VhostUserNetConfig::new(socket_path, passthrough.vm_id().to_string());
        if let Ok(mtu) = env::var("MESH_TUN_MTU") {
            vhost_config.mtu = mtu.parse()?;
        }
        spawn_vhost_user_net(vhost_config)?;
    }

    run_uds_server(
        capture_listener,
        UdsServerConfig::new(resolved_socket_path, style),
        tun_tx,
        fallback_rx,
    )
    .await
}

fn mesh_tun_config_from_env() -> Result<MeshTunConfig, anyhow::Error> {
    let mut config = MeshTunConfig::default();
    if let Ok(name) = env::var("MESH_TUN_NAME") {
        if !name.is_empty() {
            config.name = Some(name);
        }
    }
    if let Ok(address) = env::var("MESH_TUN_ADDRESS") {
        config.address = address.parse()?;
    }
    if let Ok(prefix_len) = env::var("MESH_TUN_PREFIX_LEN") {
        config.prefix_len = prefix_len.parse()?;
    }
    if let Ok(mtu) = env::var("MESH_TUN_MTU") {
        config.mtu = mtu.parse()?;
    }
    if let Ok(enabled) = env::var("MESH_TUN_TCP_REWRITE") {
        config.tcp_rewrite = env_value_truthy(&enabled);
    }
    if let Ok(proxy_addr) = env::var("MESH_TUN_TCP_REWRITE_PROXY_ADDR") {
        config.tcp_rewrite_config.proxy_addr = proxy_addr.parse()?;
    }
    if let Ok(port_range) = env::var("MESH_TUN_TCP_REWRITE_PORTS") {
        let Some((first, last)) = port_range.split_once('-') else {
            anyhow::bail!("MESH_TUN_TCP_REWRITE_PORTS must be FIRST-LAST");
        };
        config.tcp_rewrite_config.first_port = first.parse()?;
        config.tcp_rewrite_config.last_port = last.parse()?;
    }
    if let Ok(vm_id) = env::var("MESH_TUN_VM_ID") {
        if !vm_id.is_empty() {
            config.vm_id = vm_id;
        }
    }
    Ok(config)
}

fn parse_ipv4_cidr(value: &str) -> Result<(Ipv4Addr, u8), anyhow::Error> {
    let Some((addr, prefix_len)) = value.split_once('/') else {
        anyhow::bail!("expected IPv4 CIDR, got {value}");
    };
    let prefix_len = prefix_len.parse::<u8>()?;
    if prefix_len > 32 {
        anyhow::bail!("invalid IPv4 prefix length {prefix_len}");
    }
    Ok((addr.parse()?, prefix_len))
}

fn env_truthy(name: &str) -> bool {
    env::var(name)
        .map(|value| env_value_truthy(&value))
        .unwrap_or(false)
}

fn env_value_truthy(value: &str) -> bool {
    matches!(value, "1" | "true" | "yes" | "on")
}

fn init_telemetry() -> mesh::local_trace::LogBuffer {
    let filter = EnvFilter::from_default_env();
    let (filter, reload_handle) = reload::Layer::new(filter);

    let buffer_layer = mesh::local_trace::LogBufferLayer::new();
    let log_buffer = buffer_layer.buffer();

    Registry::default().with(filter).with(buffer_layer).init();

    // Store the reload handle globally
    let _ = mesh::local_trace::TRACING_RELOAD_HANDLE.set(reload_handle);

    log_buffer
}

fn get_run_dir() -> PathBuf {
    if let Ok(dir) = env::var("MESH_TUN_RUN") {
        PathBuf::from(dir)
    } else {
        let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(format!("{}/.run/mesh-tun", home))
    }
}

fn resolve_and_bind_uds(
    app_name: &str,
    path_str: &str,
    specific_fd_var: &str,
    fallback_fd_var: Option<&str>,
) -> Result<UnixListener, anyhow::Error> {
    let fd_str = env::var(specific_fd_var)
        .ok()
        .or_else(|| fallback_fd_var.and_then(|var| env::var(var).ok()));

    if let Some(fd_str) = fd_str {
        if let Ok(fd) = fd_str.parse::<i32>() {
            tracing::info!("Using activated listener FD {} for {}", fd, path_str);
            let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
            std_listener.set_nonblocking(true)?;
            let listener = UnixListener::from_std(std_listener)?;
            return Ok(listener);
        }
    }

    let actual_path = if path_str.starts_with('_') {
        path_str.replacen('_', "\0", 1)
    } else if path_str.starts_with('/') {
        path_str.to_string()
    } else {
        let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let dir = format!("{}/.run/{}", home, app_name);
        let _ = std::fs::create_dir_all(&dir);
        format!("{}/{}", dir, path_str)
    };

    if !actual_path.starts_with('\0') {
        let path = std::path::Path::new(&actual_path);
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }
    let listener = UnixListener::bind(&actual_path)?;
    tracing::info!("Listening on UDS {:?}", actual_path);

    if !actual_path.starts_with('\0') {
        // Set permissions to 0660
        let mut perms = std::fs::metadata(&actual_path)?.permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o660);
        std::fs::set_permissions(&actual_path, perms)?;
    }

    Ok(listener)
}
