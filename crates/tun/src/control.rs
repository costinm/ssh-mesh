use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct ControlServerConfig {
    pub socket_path: PathBuf,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PacketCaptureSpec {
    pub vm_id: String,
    pub netns_path: PathBuf,
    pub if_name: Option<String>,
}

pub async fn run_control_server(
    config: ControlServerConfig,
    tun_tx: mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    bind_parent(&config.socket_path).await?;
    let listener = UnixListener::bind(&config.socket_path)?;
    tracing::info!(socket = %config.socket_path.display(), "mesh-tun control socket started");

    loop {
        let (stream, _) = listener.accept().await?;
        let tun_tx = tun_tx.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_control_client(stream, tun_tx).await {
                tracing::warn!(%error, "mesh-tun control client disconnected");
            }
        });
    }
}

async fn bind_parent(path: &Path) -> Result<(), anyhow::Error> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if tokio::fs::try_exists(path).await.unwrap_or(false) {
        tokio::fs::remove_file(path).await?;
    }
    Ok(())
}

async fn handle_control_client(
    stream: tokio::net::UnixStream,
    tun_tx: mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    let std_stream = stream.into_std()?;
    tokio::task::spawn_blocking(move || {
        let reader_stream = std_stream.try_clone()?;
        let mut reader = BufReader::new(reader_stream);
        let mut writer = std_stream;
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                return Ok::<(), anyhow::Error>(());
            }
            let request = line.trim();
            if request.is_empty() {
                continue;
            }
            match parse_control_request(request) {
                Ok(ControlRequest::CapturePacket(spec)) => {
                    let result = start_packet_capture(spec, tun_tx.clone());
                    match result {
                        Ok(()) => writeln!(writer, "ok")?,
                        Err(error) => writeln!(writer, "error {error}")?,
                    }
                }
                Ok(ControlRequest::Ping) => {
                    writeln!(writer, "ok pong")?;
                }
                Err(error) => {
                    writeln!(writer, "error {error}")?;
                }
            }
            writer.flush()?;
        }
    })
    .await?
}

enum ControlRequest {
    Ping,
    CapturePacket(PacketCaptureSpec),
}

fn parse_control_request(request: &str) -> Result<ControlRequest, anyhow::Error> {
    let mut fields = request.split_whitespace();
    match fields.next() {
        Some("ping") => Ok(ControlRequest::Ping),
        Some("capture-packet" | "capture-afpacket" | "capture-af_socket") => {
            let mut vm_id = None;
            let mut netns_path = None;
            let mut if_name = None;
            for field in fields {
                let Some((key, value)) = field.split_once('=') else {
                    anyhow::bail!("expected key=value field, got {field}");
                };
                match key {
                    "vm_id" => vm_id = Some(value.to_string()),
                    "netns" => netns_path = Some(PathBuf::from(value)),
                    "if" => if_name = Some(value.to_string()),
                    other => anyhow::bail!("unknown capture-packet field {other}"),
                }
            }
            Ok(ControlRequest::CapturePacket(PacketCaptureSpec {
                vm_id: vm_id.unwrap_or_else(|| "netns".to_string()),
                netns_path: netns_path
                    .ok_or_else(|| anyhow::anyhow!("capture-packet requires netns=/path"))?,
                if_name,
            }))
        }
        Some(other) => anyhow::bail!("unknown control command {other}"),
        None => anyhow::bail!("empty control command"),
    }
}

fn start_packet_capture(
    spec: PacketCaptureSpec,
    tun_tx: mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    let spec = Arc::new(spec);
    std::thread::Builder::new()
        .name(format!("mesh-tun-afpacket-{}", spec.vm_id))
        .spawn(move || {
            if let Err(error) = packet_capture_thread(&spec, tun_tx) {
                tracing::warn!(vm_id = %spec.vm_id, %error, "AF_PACKET capture stopped");
            }
        })?;
    Ok(())
}

fn packet_capture_thread(
    spec: &PacketCaptureSpec,
    tun_tx: mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    let netns = File::open(&spec.netns_path)?;
    setns_net(netns.as_raw_fd())?;
    let socket = open_af_packet_socket()?;
    if let Some(if_name) = &spec.if_name {
        bind_packet_socket_to_interface(socket.as_raw_fd(), if_name)?;
    }

    let mut buf = vec![0u8; 65535];
    loop {
        let n = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_TRUNC,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let n = n as usize;
        if let Some(packet) = ethernet_payload_to_ip(&buf[..n]) {
            tun_tx
                .send(packet)
                .map_err(|_| anyhow::anyhow!("TUN input queue closed"))?;
        }
    }
}

fn setns_net(fd: RawFd) -> Result<(), anyhow::Error> {
    let rc = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn open_af_packet_socket() -> Result<OwnedFd, anyhow::Error> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn bind_packet_socket_to_interface(fd: RawFd, if_name: &str) -> Result<(), anyhow::Error> {
    let name = std::ffi::CString::new(if_name)?;
    let if_index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if if_index == 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = if_index as i32;

    let rc = unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_ll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn ethernet_payload_to_ip(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 14 {
        return None;
    }
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0800 | 0x86dd => Some(frame[14..].to_vec()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_packet_capture_command() {
        let ControlRequest::CapturePacket(spec) =
            parse_control_request("capture-packet vm_id=app1 netns=/proc/123/ns/net if=eth0")
                .unwrap()
        else {
            panic!("expected capture-packet");
        };
        assert_eq!(spec.vm_id, "app1");
        assert_eq!(spec.netns_path, PathBuf::from("/proc/123/ns/net"));
        assert_eq!(spec.if_name.as_deref(), Some("eth0"));
    }

    #[test]
    fn parses_afsocket_capture_alias() {
        let ControlRequest::CapturePacket(spec) =
            parse_control_request("capture-af_socket vm_id=app2 netns=/proc/456/ns/net").unwrap()
        else {
            panic!("expected capture-packet");
        };
        assert_eq!(spec.vm_id, "app2");
        assert_eq!(spec.netns_path, PathBuf::from("/proc/456/ns/net"));
        assert_eq!(spec.if_name, None);
    }
}
