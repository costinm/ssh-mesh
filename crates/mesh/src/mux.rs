//! OpenSSH-compatible local mux framing and Unix descriptor passing.
//!
//! These primitives are transport-neutral. `ssh-mesh` uses them to adapt a
//! local unencrypted mux session to SSH, while local mesh services can use the
//! same framing directly between processes, UIDs, and VMs.

use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use anyhow::{Context, Result};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, UnixAddr, recvmsg, sendmsg};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

pub const MUX_MSG_HELLO: u32 = 0x0000_0001;
pub const MUX_C_NEW_SESSION: u32 = 0x1000_0002;
pub const MUX_C_ALIVE_CHECK: u32 = 0x1000_0004;
pub const MUX_C_TERMINATE: u32 = 0x1000_0005;
pub const MUX_C_OPEN_FWD: u32 = 0x1000_0006;
pub const MUX_C_CLOSE_FWD: u32 = 0x1000_0007;
pub const MUX_C_NEW_STDIO_FWD: u32 = 0x1000_0008;
pub const MUX_C_STOP_LISTENING: u32 = 0x1000_0009;

pub const MUX_S_OK: u32 = 0x8000_0001;
pub const MUX_S_PERMISSION_DENIED: u32 = 0x8000_0002;
pub const MUX_S_FAILURE: u32 = 0x8000_0003;
pub const MUX_S_EXIT_MESSAGE: u32 = 0x8000_0004;
pub const MUX_S_ALIVE: u32 = 0x8000_0005;
pub const MUX_S_SESSION_OPENED: u32 = 0x8000_0006;
pub const MUX_S_REMOTE_PORT: u32 = 0x8000_0007;
pub const MUX_S_TTY_ALLOC_FAIL: u32 = 0x8000_0008;

pub const MUX_FWD_LOCAL: u32 = 1;
pub const MUX_FWD_REMOTE: u32 = 2;
pub const MUX_FWD_DYNAMIC: u32 = 3;
pub const MUX_PROTOCOL_VERSION: u32 = 4;
pub const MUX_COMPONENT: &str = "mux";
pub const SSH_COMPONENT: &str = "ssh";

// RFC 4254 connection protocol message numbers. Mesh reuses these numbers in
// metadata byte one so channel and forwarding adapters need no second enum.
pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;
pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

// RFC 4254 request and channel type names carried inside the corresponding
// SSH_MSG_GLOBAL_REQUEST and SSH_MSG_CHANNEL_OPEN payloads.
pub const SSH_REQUEST_TCPIP_FORWARD: &str = "tcpip-forward";
pub const SSH_REQUEST_CANCEL_TCPIP_FORWARD: &str = "cancel-tcpip-forward";
pub const SSH_CHANNEL_SESSION: &str = "session";
pub const SSH_CHANNEL_DIRECT_TCPIP: &str = "direct-tcpip";
pub const SSH_CHANNEL_FORWARDED_TCPIP: &str = "forwarded-tcpip";

/// Private-use SSH message number for a schema-tagged mesh RPC record.
pub const MESH_MSG_RPC: u8 = 0xcb;
pub const MESH_META_RPC: PacketMeta = PacketMeta::new(MESH_MSG_RPC, 0, 0);

/// Compatibility name for the original CBOR stream discriminator.
pub const MESH_META_CBOR: PacketMeta = MESH_META_RPC;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketMeta(pub [u8; 4]);

impl PacketMeta {
    /// Build `padding | SSH message type | flags | version` metadata.
    pub const fn new(message_type: u8, flags: u8, version: u8) -> Self {
        Self([0, message_type, flags, version])
    }

    pub const fn from_u32(value: u32) -> Self {
        Self(value.to_be_bytes())
    }
    pub const fn as_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    /// Return the SSH-compatible message type for a mesh frame.
    pub const fn message_type(self) -> Option<u8> {
        if self.0[0] == 0 && self.0[1] != 0 {
            Some(self.0[1])
        } else {
            None
        }
    }

    pub const fn flags(self) -> u8 {
        self.0[2]
    }

    pub const fn version(self) -> u8 {
        self.0[3]
    }
}

/// Method in the `ssh` component represented by a connection-layer frame type.
pub const fn ssh_method_for_type(message_type: u8) -> Option<&'static str> {
    Some(match message_type {
        SSH_MSG_GLOBAL_REQUEST => "global_request",
        SSH_MSG_REQUEST_SUCCESS => "request_success",
        SSH_MSG_REQUEST_FAILURE => "request_failure",
        SSH_MSG_CHANNEL_OPEN => "channel_open",
        SSH_MSG_CHANNEL_OPEN_CONFIRMATION => "channel_opened",
        SSH_MSG_CHANNEL_OPEN_FAILURE => "channel_open_failure",
        SSH_MSG_CHANNEL_WINDOW_ADJUST => "channel_window_adjust",
        SSH_MSG_CHANNEL_DATA => "channel_data",
        SSH_MSG_CHANNEL_EXTENDED_DATA => "channel_extended_data",
        SSH_MSG_CHANNEL_EOF => "channel_eof",
        SSH_MSG_CHANNEL_CLOSE => "channel_close",
        SSH_MSG_CHANNEL_REQUEST => "channel_request",
        SSH_MSG_CHANNEL_SUCCESS => "channel_success",
        SSH_MSG_CHANNEL_FAILURE => "channel_failure",
        _ => return None,
    })
}

/// Method in the `mux` component represented by an OpenSSH mux message ID.
pub const fn mux_method_for_type(msg_type: u32) -> Option<&'static str> {
    Some(match msg_type {
        MUX_MSG_HELLO => "hello",
        MUX_C_NEW_SESSION => "session_open",
        MUX_C_ALIVE_CHECK => "alive",
        MUX_C_TERMINATE => "terminate",
        MUX_C_OPEN_FWD => "forward_open",
        MUX_C_CLOSE_FWD => "forward_close",
        MUX_C_NEW_STDIO_FWD => "stdio_open",
        MUX_C_STOP_LISTENING => "listening_stop",
        MUX_S_OK => "ok",
        MUX_S_PERMISSION_DENIED => "permission_denied",
        MUX_S_FAILURE => "failure",
        MUX_S_EXIT_MESSAGE => "session_exit",
        MUX_S_ALIVE => "alive_response",
        MUX_S_SESSION_OPENED => "session_opened",
        MUX_S_REMOTE_PORT => "forward_port",
        MUX_S_TTY_ALLOC_FAIL => "tty_failure",
        _ => return None,
    })
}

pub fn mux_type_for_method(method: &str) -> Option<u32> {
    Some(match method {
        "hello" => MUX_MSG_HELLO,
        "session_open" => MUX_C_NEW_SESSION,
        "alive" => MUX_C_ALIVE_CHECK,
        "terminate" => MUX_C_TERMINATE,
        "forward_open" => MUX_C_OPEN_FWD,
        "forward_close" => MUX_C_CLOSE_FWD,
        "stdio_open" => MUX_C_NEW_STDIO_FWD,
        "listening_stop" => MUX_C_STOP_LISTENING,
        "ok" => MUX_S_OK,
        "permission_denied" => MUX_S_PERMISSION_DENIED,
        "failure" => MUX_S_FAILURE,
        "session_exit" => MUX_S_EXIT_MESSAGE,
        "alive_response" => MUX_S_ALIVE,
        "session_opened" => MUX_S_SESSION_OPENED,
        "forward_port" => MUX_S_REMOTE_PORT,
        "tty_failure" => MUX_S_TTY_ALLOC_FAIL,
        _ => return None,
    })
}

/// Maximum packet body accepted before allocation.
pub const MAX_MUX_PACKET_LEN: u32 = 64 * 1024;

pub async fn read_u32<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u32> {
    let mut bytes = [0; 4];
    reader
        .read_exact(&mut bytes)
        .await
        .context("read mux u32")?;
    Ok(u32::from_be_bytes(bytes))
}

pub async fn write_u32<W: AsyncWrite + Unpin>(writer: &mut W, value: u32) -> Result<()> {
    writer
        .write_all(&value.to_be_bytes())
        .await
        .context("write mux u32")
}

pub async fn read_string<R: AsyncRead + Unpin>(reader: &mut R) -> Result<String> {
    let len = read_u32(reader).await?;
    if len > MAX_MUX_PACKET_LEN {
        anyhow::bail!("mux string exceeds {} bytes", MAX_MUX_PACKET_LEN);
    }
    let mut bytes = vec![0; len as usize];
    reader
        .read_exact(&mut bytes)
        .await
        .context("read mux string")?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub async fn write_string<W: AsyncWrite + Unpin>(writer: &mut W, value: &str) -> Result<()> {
    write_u32(
        writer,
        u32::try_from(value.len()).context("mux string too large")?,
    )
    .await?;
    writer
        .write_all(value.as_bytes())
        .await
        .context("write mux string")
}

pub async fn read_bool<R: AsyncRead + Unpin>(reader: &mut R) -> Result<bool> {
    Ok(read_u32(reader).await? != 0)
}

pub async fn read_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(u32, Vec<u8>)> {
    let (meta, payload) = read_frame(reader).await?;
    Ok((meta.as_u32(), payload))
}

/// Read the shared `u32-be length | 4-byte metadata | payload` frame.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(PacketMeta, Vec<u8>)> {
    let len = read_u32(reader).await.context("read mux packet length")?;
    if !(4..=MAX_MUX_PACKET_LEN).contains(&len) {
        anyhow::bail!("invalid mux packet length {len}");
    }
    let mut body = vec![0; len as usize];
    reader
        .read_exact(&mut body)
        .await
        .context("read mux packet")?;
    let meta = PacketMeta(body[..4].try_into().expect("four byte metadata"));
    Ok((meta, body[4..].to_vec()))
}

pub fn build_packet(payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// Build a frame from explicit metadata and payload.
pub fn build_frame(meta: PacketMeta, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + payload.len());
    body.extend_from_slice(&meta.0);
    body.extend_from_slice(payload);
    build_packet(&body)
}

/// Decode one complete in-memory frame without allocating its payload.
pub fn decode_frame(frame: &[u8]) -> Result<(PacketMeta, &[u8])> {
    if frame.len() < 8 {
        anyhow::bail!("short mux frame");
    }
    let len = u32::from_be_bytes(frame[..4].try_into().expect("four byte length")) as usize;
    if !(4..=MAX_MUX_PACKET_LEN as usize).contains(&len) || frame.len() != len + 4 {
        anyhow::bail!("invalid mux frame length {len}");
    }
    let meta = PacketMeta(frame[4..8].try_into().expect("four byte metadata"));
    Ok((meta, &frame[8..]))
}

pub fn payload_with_type(msg_type: u32) -> Vec<u8> {
    msg_type.to_be_bytes().to_vec()
}

pub fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

pub fn push_string(bytes: &mut Vec<u8>, value: &str) {
    push_u32(bytes, value.len() as u32);
    bytes.extend_from_slice(value.as_bytes());
}

pub fn parse_u32(payload: &[u8], offset: usize) -> Result<(u32, usize)> {
    let end = offset.checked_add(4).context("mux u32 offset overflow")?;
    let bytes = payload.get(offset..end).context("short mux u32")?;
    Ok((
        u32::from_be_bytes(bytes.try_into().expect("four byte slice")),
        end,
    ))
}

pub fn parse_string(payload: &[u8], offset: usize) -> Result<(String, usize)> {
    let (len, start) = parse_u32(payload, offset)?;
    let end = start
        .checked_add(len as usize)
        .context("mux string offset overflow")?;
    let bytes = payload.get(start..end).context("short mux string")?;
    Ok((String::from_utf8_lossy(bytes).into_owned(), end))
}

/// Send one descriptor with the OpenSSH one-byte SCM_RIGHTS convention.
pub fn send_fd(raw_socket: RawFd, fd: RawFd) -> Result<()> {
    let marker = [0_u8];
    let iov = [IoSlice::new(&marker)];
    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    sendmsg::<UnixAddr>(raw_socket, &iov, &cmsg, MsgFlags::empty(), None)?;
    Ok(())
}

/// Receive one descriptor without blocking the Tokio executor.
pub async fn recv_fd(stream: &UnixStream) -> Result<OwnedFd> {
    loop {
        stream.readable().await?;
        let mut marker = [0_u8];
        let mut iov = [IoSliceMut::new(&mut marker)];
        let mut cmsg_space = nix::cmsg_space!(RawFd);
        match recvmsg::<UnixAddr>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_space),
            MsgFlags::empty(),
        ) {
            Ok(message) => {
                for cmsg in message.cmsgs()? {
                    if let ControlMessageOwned::ScmRights(fds) = cmsg
                        && let Some(fd) = fds.into_iter().next()
                    {
                        // SAFETY: SCM_RIGHTS transfers a new descriptor owned by this process.
                        return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
                    }
                }
                anyhow::bail!("mux descriptor message contained no descriptor");
            }
            Err(nix::errno::Errno::EAGAIN) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_and_payload_helpers_round_trip() {
        let mut payload = payload_with_type(MUX_C_ALIVE_CHECK);
        push_u32(&mut payload, 7);
        push_string(&mut payload, "mesh");
        let packet = build_packet(&payload);
        assert_eq!(
            u32::from_be_bytes(packet[..4].try_into().unwrap()),
            payload.len() as u32
        );
        let (id, offset) = parse_u32(&payload, 4).unwrap();
        let (name, end) = parse_string(&payload, offset).unwrap();
        assert_eq!((id, name, end), (7, "mesh".to_owned(), payload.len()));
    }

    #[test]
    fn mesh_metadata_is_distinct_from_openssh_hello() {
        assert_eq!(PacketMeta::from_u32(MUX_MSG_HELLO).message_type(), None);
        assert_eq!(MESH_META_RPC.message_type(), Some(MESH_MSG_RPC));
        assert_eq!(MESH_META_RPC.flags(), 0);
        assert_eq!(MESH_META_RPC.version(), 0);
        assert_eq!(mux_method_for_type(MUX_C_NEW_SESSION), Some("session_open"));
        assert_eq!(mux_type_for_method("session_open"), Some(MUX_C_NEW_SESSION));
    }

    #[test]
    fn ssh_message_numbers_are_frame_types() {
        let frame = build_frame(PacketMeta::new(SSH_MSG_CHANNEL_OPEN, 0, 0), b"session");
        let (meta, payload) = decode_frame(&frame).unwrap();
        assert_eq!(meta.message_type(), Some(SSH_MSG_CHANNEL_OPEN));
        assert_eq!(
            ssh_method_for_type(SSH_MSG_CHANNEL_OPEN),
            Some("channel_open")
        );
        assert_eq!(payload, b"session");
    }
}
