//! AF_UNIX `SOCK_SEQPACKET` transport for tagged-CBOR records and `SCM_RIGHTS`.
//!
//! A packet is one complete CBOR record.  Unlike a byte stream, ancillary
//! data is received with the record that names it, so descriptor-passing
//! requests cannot be separated from their payload by buffering.

use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use anyhow::{Context, Result, bail};
use nix::cmsg_space;
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use tokio::io::unix::AsyncFd;

use crate::cbor::{MAX_RECORD_LEN, decode_record, encode_record};
use crate::tagged::TaggedRecord;

pub const MAX_FDS_PER_PACKET: usize = 16;

/// A complete packet and the descriptors atomically received with it.
pub struct ReceivedPacket {
    pub bytes: Vec<u8>,
    pub fds: Vec<OwnedFd>,
}

/// Tokio-integrated AF_UNIX `SOCK_SEQPACKET` connection.
pub struct UnixSeqpacket {
    inner: AsyncFd<OwnedFd>,
}

/// Tokio-integrated AF_UNIX `SOCK_SEQPACKET` listener.
pub struct UnixSeqpacketListener {
    inner: AsyncFd<OwnedFd>,
}

fn socket_addr(path: &Path) -> Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.contains(&0) || bytes.len() >= 108 {
        bail!("invalid AF_UNIX socket path {}", path.display());
    }
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes.iter()) {
        *dst = *src as libc::c_char;
    }
    let len = (std::mem::size_of_val(&addr.sun_family) + bytes.len() + 1) as libc::socklen_t;
    Ok((addr, len))
}

fn new_socket() -> Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("create AF_UNIX SOCK_SEQPACKET socket");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

impl UnixSeqpacketListener {
    pub fn bind(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let fd = new_socket()?;
        let (addr, len) = socket_addr(path)?;
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_un).cast(),
                len,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("bind seqpacket socket {}", path.display()));
        }
        if unsafe { libc::listen(fd.as_raw_fd(), 32) } < 0 {
            return Err(std::io::Error::last_os_error()).context("listen on seqpacket socket");
        }
        Ok(Self {
            inner: AsyncFd::new(fd)?,
        })
    }

    pub async fn accept(&self) -> Result<UnixSeqpacket> {
        loop {
            let mut ready = self.inner.readable().await?;
            match ready.try_io(|fd| {
                let accepted = unsafe {
                    libc::accept4(
                        fd.as_raw_fd(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    )
                };
                if accepted < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(unsafe { OwnedFd::from_raw_fd(accepted) })
                }
            }) {
                Ok(Ok(fd)) => {
                    return Ok(UnixSeqpacket {
                        inner: AsyncFd::new(fd)?,
                    });
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => continue,
            }
        }
    }
}

impl UnixSeqpacket {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let fd = new_socket()?;
        let (addr, len) = socket_addr(path.as_ref())?;
        let ret = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_un).cast(),
                len,
            )
        };
        if ret < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("connect seqpacket socket {}", path.as_ref().display()));
        }
        let inner = AsyncFd::new(fd)?;
        if ret < 0 {
            let _ = inner.writable().await?;
            let mut error: libc::c_int = 0;
            let mut error_len = std::mem::size_of_val(&error) as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    inner.get_ref().as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut error as *mut libc::c_int).cast(),
                    &mut error_len,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("read seqpacket connect error");
            }
            if error != 0 {
                return Err(std::io::Error::from_raw_os_error(error))
                    .context("connect seqpacket socket");
            }
        }
        Ok(Self { inner })
    }

    pub fn peer_cred(&self) -> Result<(u32, u32)> {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                self.inner.get_ref().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error()).context("read seqpacket peer credentials");
        }
        Ok((cred.uid, cred.gid))
    }

    pub async fn send_packet(&self, bytes: &[u8], fds: &[RawFd]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_RECORD_LEN {
            bail!("invalid seqpacket payload length {}", bytes.len());
        }
        loop {
            let mut ready = self.inner.writable().await?;
            match ready.try_io(|fd| {
                let iov = [IoSlice::new(bytes)];
                let cmsgs = (!fds.is_empty()).then_some(ControlMessage::ScmRights(fds));
                let sent = match cmsgs.as_ref() {
                    Some(cmsg) => sendmsg::<()>(
                        fd.as_raw_fd(),
                        &iov,
                        std::slice::from_ref(cmsg),
                        MsgFlags::MSG_DONTWAIT,
                        None,
                    ),
                    None => sendmsg::<()>(fd.as_raw_fd(), &iov, &[], MsgFlags::MSG_DONTWAIT, None),
                }
                .map_err(std::io::Error::from)?;
                if sent == bytes.len() {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "short SOCK_SEQPACKET send",
                    ))
                }
            }) {
                Ok(result) => return result.map_err(Into::into),
                Err(_) => continue,
            }
        }
    }

    pub async fn recv_packet(&self) -> Result<Option<ReceivedPacket>> {
        loop {
            let mut ready = self.inner.readable().await?;
            match ready.try_io(|fd| {
                let mut bytes = vec![0; MAX_RECORD_LEN];
                let mut iov = [IoSliceMut::new(&mut bytes)];
                let mut space = cmsg_space!([RawFd; MAX_FDS_PER_PACKET]);
                let (received, fds) = {
                    let message = recvmsg::<()>(
                        fd.as_raw_fd(),
                        &mut iov,
                        Some(&mut space),
                        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_CMSG_CLOEXEC,
                    )
                    .map_err(std::io::Error::from)?;
                    if message.flags.contains(MsgFlags::MSG_TRUNC)
                        || message.flags.contains(MsgFlags::MSG_CTRUNC)
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "truncated SOCK_SEQPACKET message or descriptors",
                        ));
                    }
                    let mut fds = Vec::new();
                    for cmsg in message.cmsgs().map_err(std::io::Error::from)? {
                        if let ControlMessageOwned::ScmRights(rights) = cmsg {
                            fds.extend(
                                rights
                                    .into_iter()
                                    .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
                            );
                        }
                    }
                    (message.bytes, fds)
                };
                if received == 0 {
                    Ok(None)
                } else {
                    bytes.truncate(received);
                    Ok(Some(ReceivedPacket { bytes, fds }))
                }
            }) {
                Ok(result) => return result.map_err(Into::into),
                Err(_) => continue,
            }
        }
    }

    pub async fn send_cbor_record(&self, record: &TaggedRecord, fds: &[RawFd]) -> Result<()> {
        self.send_packet(&encode_record(record)?, fds).await
    }

    pub async fn recv_cbor_record(&self) -> Result<Option<(TaggedRecord, Vec<OwnedFd>)>> {
        let Some(packet) = self.recv_packet().await? else {
            return Ok(None);
        };
        Ok(Some((
            decode_record(&packet.bytes).context("decode seqpacket tagged-CBOR record")?,
            packet.fds,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tagged::NameOrTag;

    #[tokio::test]
    async fn cbor_record_and_rights_arrive_in_one_packet() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("mesh.seqpacket");
        let listener = UnixSeqpacketListener::bind(&path).unwrap();
        let client = UnixSeqpacket::connect(&path).await.unwrap();
        let server = listener.accept().await.unwrap();
        let (passed, _other) = std::os::unix::net::UnixStream::pair().unwrap();
        let record = TaggedRecord {
            component: NameOrTag::Name("mesh-init".to_string()),
            method: NameOrTag::Name("start_terminal".to_string()),
            id: Some(serde_json::json!(7)),
            ..Default::default()
        };

        client
            .send_cbor_record(&record, &[passed.as_raw_fd()])
            .await
            .unwrap();
        let (received, fds) = server.recv_cbor_record().await.unwrap().unwrap();
        assert_eq!(received.id, record.id);
        assert_eq!(fds.len(), 1);
        assert!(fds[0].as_raw_fd() >= 0);
    }
}
