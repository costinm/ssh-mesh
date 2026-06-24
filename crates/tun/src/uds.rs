use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UdsStyle {
    Qemu,
    VirtioUser,
}

impl UdsStyle {
    pub fn from_env_value(value: &str) -> Result<Self, anyhow::Error> {
        match value {
            "qemu" | "qemu-stream" | "stream" => Ok(Self::Qemu),
            "virtio-user" | "vhost-user" | "vhost" => Ok(Self::VirtioUser),
            other => anyhow::bail!("unsupported MESH_TUN_UDS_STYLE={other}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UdsServerConfig {
    pub socket_path: PathBuf,
    pub style: UdsStyle,
    pub host_mac: [u8; 6],
}

impl UdsServerConfig {
    pub fn new(socket_path: impl Into<PathBuf>, style: UdsStyle) -> Self {
        Self {
            socket_path: socket_path.into(),
            style,
            host_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        }
    }
}

pub async fn run_uds_server(
    config: UdsServerConfig,
    tun_tx: mpsc::UnboundedSender<Vec<u8>>,
    stack_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    if config.style == UdsStyle::VirtioUser {
        anyhow::bail!(
            "virtio-user/vhost-user UDS mode needs vhost-user vring negotiation; use MESH_TUN_UDS_STYLE=qemu for qemu stream sockets"
        );
    }

    if let Some(parent) = config.socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if tokio::fs::try_exists(&config.socket_path)
        .await
        .unwrap_or(false)
    {
        tokio::fs::remove_file(&config.socket_path).await?;
    }

    let listener = UnixListener::bind(&config.socket_path)?;
    tracing::info!(
        socket = %config.socket_path.display(),
        style = ?config.style,
        "mesh-tun UDS listener started"
    );

    let stack_rx = Arc::new(tokio::sync::Mutex::new(stack_rx));
    loop {
        let (stream, _) = listener.accept().await?;
        let tun_tx = tun_tx.clone();
        let stack_rx = stack_rx.clone();
        let host_mac = config.host_mac;
        tokio::spawn(async move {
            if let Err(error) = serve_qemu_stream(stream, host_mac, tun_tx, stack_rx).await {
                tracing::warn!(%error, "mesh-tun UDS client disconnected");
            }
        });
    }
}

async fn serve_qemu_stream(
    stream: UnixStream,
    host_mac: [u8; 6],
    tun_tx: mpsc::UnboundedSender<Vec<u8>>,
    stack_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
) -> Result<(), anyhow::Error> {
    let (mut reader, mut writer) = stream.into_split();
    let guest_mac = Arc::new(Mutex::new(None::<[u8; 6]>));

    let read_guest_mac = guest_mac.clone();
    let read_task = tokio::spawn(async move {
        loop {
            let frame = read_qemu_frame(&mut reader).await?;
            if let Some((packet, src_mac)) = ethernet_to_ip(&frame) {
                *read_guest_mac.lock().unwrap() = Some(src_mac);
                tun_tx
                    .send(packet)
                    .map_err(|_| anyhow::anyhow!("TUN input queue closed"))?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });

    let write_guest_mac = guest_mac;
    let write_task = tokio::spawn(async move {
        loop {
            let packet = {
                let mut rx = stack_rx.lock().await;
                rx.recv()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("TUN output queue closed"))?
            };
            let dst_mac = write_guest_mac
                .lock()
                .unwrap()
                .unwrap_or([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
            let frame = ip_to_ethernet(&packet, host_mac, dst_mac)?;
            write_qemu_frame(&mut writer, &frame).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });

    tokio::select! {
        result = read_task => result??,
        result = write_task => result??,
    }
    Ok(())
}

async fn read_qemu_frame<R>(reader: &mut R) -> Result<Vec<u8>, anyhow::Error>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u32().await? as usize;
    if len == 0 || len > 65535 {
        anyhow::bail!("invalid qemu frame length: {len}");
    }
    let mut frame = vec![0u8; len];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

async fn write_qemu_frame<W>(writer: &mut W, frame: &[u8]) -> Result<(), anyhow::Error>
where
    W: AsyncWrite + Unpin,
{
    if frame.len() > u32::MAX as usize {
        anyhow::bail!("frame too large: {}", frame.len());
    }
    writer.write_u32(frame.len() as u32).await?;
    writer.write_all(frame).await?;
    writer.flush().await?;
    Ok(())
}

fn ethernet_to_ip(frame: &[u8]) -> Option<(Vec<u8>, [u8; 6])> {
    if frame.len() < 14 {
        return None;
    }
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    match ethertype {
        0x0800 | 0x86dd => Some((frame[14..].to_vec(), src_mac)),
        _ => None,
    }
}

fn ip_to_ethernet(
    packet: &[u8],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Result<Vec<u8>, anyhow::Error> {
    if packet.is_empty() {
        anyhow::bail!("empty IP packet");
    }
    let ethertype = match packet[0] >> 4 {
        4 => 0x0800u16,
        6 => 0x86ddu16,
        version => anyhow::bail!("unsupported IP version in TUN packet: {version}"),
    };
    let mut frame = Vec::with_capacity(14 + packet.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(packet);
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_round_trip_preserves_ip_payload() {
        let packet = vec![
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let src = [0x02, 0, 0, 0, 0, 1];
        let dst = [0x02, 0, 0, 0, 0, 2];
        let frame = ip_to_ethernet(&packet, src, dst).unwrap();
        let (decoded, observed_src) = ethernet_to_ip(&frame).unwrap();
        assert_eq!(decoded, packet);
        assert_eq!(observed_src, src);
    }
}
