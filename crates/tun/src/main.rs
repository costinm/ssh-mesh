use mesh_tun::control::{run_control_server, ControlServerConfig};
use mesh_tun::flow::MeshPassthrough;
use mesh_tun::uds::{run_uds_server, UdsServerConfig, UdsStyle};
use mesh_tun::vhost_user::{spawn_vhost_user_net, VhostUserNetConfig};
use mesh_tun::{MeshTun, MeshTunConfig};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
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
    let socket_path = PathBuf::from(
        env::var("MESH_TUN_SOCKET").unwrap_or_else(|_| "/tmp/mesh-tun-qemu.sock".into()),
    );
    let style = UdsStyle::from_env_value(
        &env::var("MESH_TUN_UDS_STYLE").unwrap_or_else(|_| "qemu".to_string()),
    )?;
    let control_socket = PathBuf::from(
        env::var("MESH_TUN_CONTROL_SOCKET").unwrap_or_else(|_| "/tmp/mesh-tun-control.sock".into()),
    );
    let vhost_socket = env::var("MESH_TUN_VHOST_SOCKET")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            env_truthy("MESH_TUN_ENABLE_VHOST").then(|| PathBuf::from("/tmp/mesh-tun-vhost.sock"))
        });
    let tun = MeshTun::new(config)?;
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (injector, tun_tx, stack_rx) = tun
        .run_with_channels(
            passthrough.clone(),
            passthrough.clone(),
            passthrough.clone(),
            tx,
            rx,
        )
        .await?;
    passthrough.set_injector(injector);

    let control_tx = tun_tx.clone();
    tokio::spawn(async move {
        if let Err(error) = run_control_server(
            ControlServerConfig {
                socket_path: control_socket,
            },
            control_tx,
        )
        .await
        {
            tracing::error!(%error, "mesh-tun control socket stopped");
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

    run_uds_server(UdsServerConfig::new(socket_path, style), tun_tx, stack_rx).await
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
    if let Ok(tcp_sockets) = env::var("MESH_TUN_TCP_SOCKETS") {
        config.tcp_sockets = tcp_sockets.parse()?;
    }
    if let Ok(udp_sockets) = env::var("MESH_TUN_UDP_SOCKETS") {
        config.udp_sockets = udp_sockets.parse()?;
    }
    if let Ok(vm_id) = env::var("MESH_TUN_VM_ID") {
        if !vm_id.is_empty() {
            config.vm_id = vm_id;
        }
    }
    Ok(config)
}

fn env_truthy(name: &str) -> bool {
    matches!(
        env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("yes") | Ok("on")
    )
}
