use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use mesh::config::{AppConfig, DEFAULT_MESH_TUN_MTU, NetworkBackend, NetworkConfig};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct NetworkSidecar {
    pub backend: NetworkBackend,
    pub pid: u32,
}

pub fn start_network_sidecar(
    config: &AppConfig,
    service_pid: u32,
    cgroup_path: &str,
) -> Result<Option<NetworkSidecar>, anyhow::Error> {
    match config.network.backend {
        NetworkBackend::None => Ok(None),
        NetworkBackend::Pasta => start_pasta(
            &config.name,
            &config.network,
            service_pid,
            cgroup_path,
            config.uid,
            config.gid,
        )
        .map(Some),
        NetworkBackend::MeshTun => Ok(None),
    }
}

pub fn attach_mesh_tun(
    service_name: &str,
    config: &NetworkConfig,
    netns_path: &str,
    userns_path: Option<&str>,
) -> Result<(), anyhow::Error> {
    let socket_path = config
        .control_socket
        .clone()
        .or_else(|| std::env::var("MESH_TUN_CONTROL_SOCKET").ok())
        .unwrap_or_else(|| "/tmp/mesh-tun-control.sock".to_string());
    let if_name = config.if_name.as_deref().unwrap_or("tap0");
    let address = config.address.as_deref().unwrap_or("10.5.0.2/24");
    let gateway = config.gateway.as_deref().unwrap_or("10.5.0.1");
    let route = if config.default_route {
        "default"
    } else {
        "none"
    };

    let mut request = format!(
        "capture-tap vm_id={} netns={} if={} setup=tap addr={} gw={} route={}",
        shell_field(service_name),
        shell_field(netns_path),
        shell_field(if_name),
        shell_field(address),
        shell_field(gateway),
        route
    );
    request.push_str(" mtu=");
    request.push_str(&config.mtu.unwrap_or(DEFAULT_MESH_TUN_MTU).to_string());
    if let Some(port) = config.egress_redirect_port {
        request.push_str(" egress_port=");
        request.push_str(&port.to_string());
    }
    if let Some(uid) = config.egress_redirect_uid {
        request.push_str(" egress_uid=");
        request.push_str(&uid.to_string());
    }
    if let Some(userns_path) = userns_path {
        request.push_str(" userns=");
        request.push_str(&shell_field(userns_path));
    }
    request.push('\n');

    let mut stream = std::os::unix::net::UnixStream::connect(&socket_path).map_err(|error| {
        anyhow::anyhow!("connect mesh-tun control socket {socket_path}: {error}")
    })?;
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response)?;
    if response.trim() == "ok" {
        info!(
            "Attached service '{}' netns {} to mesh-tun via {}",
            service_name, netns_path, socket_path
        );
        return Ok(());
    }
    anyhow::bail!(
        "mesh-tun attach failed for service '{}': {}",
        service_name,
        response.trim()
    )
}

fn start_pasta(
    service_name: &str,
    config: &NetworkConfig,
    service_pid: u32,
    cgroup_path: &str,
    drop_uid: Option<u32>,
    drop_gid: Option<u32>,
) -> Result<NetworkSidecar, anyhow::Error> {
    // pasta is intentionally modeled as a sidecar backend here so it can
    // validate the host-owned lifecycle and namespace attachment shape without
    // baking pasta-specific assumptions into mesh-init. The mesh-tun backend
    // should attach through the registered namespace fd stored on
    // ManagedProcess, not by requiring NET_ADMIN inside the container.
    let command = config.command.as_deref().unwrap_or("pasta");
    let args = if config.args.is_empty() {
        vec!["{pid}".to_string()]
    } else {
        config.args.clone()
    };

    let mut cmd = Command::new(command);
    for arg in args {
        cmd.arg(expand_network_template(&arg, service_name, service_pid));
    }
    for (key, value) in &config.env {
        cmd.env(
            key,
            expand_network_template(value, service_name, service_pid),
        );
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    // A1: Drop privileges before exec. Without this, the pasta sidecar (which
    // runs a config-supplied command) inherits the daemon's UID (root) and all
    // supplementary groups. A USER_INIT config could set command="/bin/sh" and
    // get a root shell.
    //
    // We use pre_exec instead of cmd.uid()/cmd.gid() so that setgroups(0,NULL)
    // runs while we still have CAP_SETGID.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(move || {
                // Clear supplementary groups (needs CAP_SETGID)
                let ret = libc::setgroups(0, std::ptr::null());
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() != Some(libc::EPERM) {
                        return Err(err);
                    }
                }
                if let Some(gid) = drop_gid {
                    if libc::setresgid(gid, gid, gid) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                if let Some(uid) = drop_uid {
                    if libc::setresuid(uid, uid, uid) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let child = cmd.spawn().map_err(|error| {
        anyhow::anyhow!(
            "failed to start pasta network sidecar for service '{}': {}",
            service_name,
            error
        )
    })?;
    let pid = child.id();
    if let Err(error) = crate::cgroup::move_to_cgroup(pid, cgroup_path) {
        warn!(
            "Failed to move pasta sidecar PID {} for '{}' to cgroup {}: {}",
            pid, service_name, cgroup_path, error
        );
    }

    info!(
        "Started pasta network sidecar for service '{}' with PID {}",
        service_name, pid
    );
    Ok(NetworkSidecar {
        backend: NetworkBackend::Pasta,
        pid,
    })
}

fn expand_network_template(value: &str, service_name: &str, service_pid: u32) -> String {
    value
        .replace("{name}", service_name)
        .replace("{pid}", &service_pid.to_string())
        .replace("{netns}", &format!("/proc/{}/ns/net", service_pid))
        .replace("{userns}", &format!("/proc/{}/ns/user", service_pid))
}

fn shell_field(value: &str) -> String {
    value.replace(char::is_whitespace, "_")
}

#[cfg(test)]
mod tests {
    use super::expand_network_template;

    #[test]
    fn expands_network_templates() {
        assert_eq!(
            expand_network_template("--ns={netns}:{userns}:{pid}:{name}", "app1", 1234),
            "--ns=/proc/1234/ns/net:/proc/1234/ns/user:1234:app1"
        );
    }
}
