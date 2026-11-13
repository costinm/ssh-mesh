//! Tier-2 `AsyncRead + AsyncWrite` stream framing over self-delimiting envelope headers.
//!
//! Each direction of a mesh handler stream begins with one self-delimiting envelope map
//! followed by optional raw body bytes and `FIN`. [`read_envelope_prefix`] decodes the
//! opening envelope in a single pass via [`mesh_api::envelope::decode_envelope_prefix`]
//! and returns a [`FramedStream`] that yields any prefetched body bytes before polling
//! the underlying stream.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use mesh_api::envelope::{MAX_ENVELOPE_BYTES, Name, PrefixDecode, Record, decode_envelope_prefix};

/// Owned copy of a decoded opening [`Record`] envelope.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OwnedEnvelope {
    /// Raw bytes of the envelope header (`buf[..body_offset]`).
    pub raw_header: Vec<u8>,
    /// Correlation identifier (`key 3` or `"id"`).
    pub id: Option<u64>,
    /// Request timeout in milliseconds (`key 8` or `"timeout"`).
    pub timeout: Option<u64>,
}

impl OwnedEnvelope {
    /// Borrow the parsed [`Record`] view over [`Self::raw_header`].
    pub fn record(&self) -> Option<Record<'_>> {
        match decode_envelope_prefix(&self.raw_header) {
            PrefixDecode::Complete { record, .. } => Some(record),
            _ => None,
        }
    }

    /// Borrow the component identifier.
    pub fn component(&self) -> Option<Name<'_>> {
        self.record()?.component
    }

    /// Borrow the method identifier.
    pub fn method(&self) -> Option<Name<'_>> {
        self.record()?.method
    }
}

/// Asynchronous stream wrapper after the opening envelope has been decoded.
///
/// Any initial body bytes that arrived in the same read as the opening envelope
/// (`&buf[body_offset..]`) are drained first before polling the inner stream `S`.
pub struct FramedStream<S> {
    stream: S,
    prefetched: Vec<u8>,
    pos: usize,
}

impl<S> FramedStream<S> {
    /// Wrap `stream` with `prefetched` initial body bytes.
    pub fn new(stream: S, prefetched: Vec<u8>) -> Self {
        Self {
            stream,
            prefetched,
            pos: 0,
        }
    }

    /// Borrow the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Mutably borrow the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Unwrap into the underlying stream and any unconsumed prefetched bytes.
    pub fn into_parts(mut self) -> (S, Vec<u8>) {
        let remaining = if self.pos < self.prefetched.len() {
            self.prefetched.split_off(self.pos)
        } else {
            Vec::new()
        };
        (self.stream, remaining)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FramedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefetched.len() {
            let rem = &self.prefetched[self.pos..];
            let to_copy = rem.len().min(buf.remaining());
            buf.put_slice(&rem[..to_copy]);
            self.pos += to_copy;
            if self.pos >= self.prefetched.len() {
                self.prefetched.clear();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FramedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Read from `stream` until a complete opening envelope map is decoded in a single pass,
/// returning `(OwnedEnvelope, FramedStream<S>)` where `FramedStream` starts at the exact
/// first byte of the raw stream body.
pub async fn read_envelope_prefix<S>(stream: S) -> io::Result<(OwnedEnvelope, FramedStream<S>)>
where
    S: AsyncRead + Unpin,
{
    let mut stream = stream;
    let mut buffer = Vec::with_capacity(256);
    let mut chunk = [0u8; 2048];
    loop {
        match decode_envelope_prefix(&buffer) {
            PrefixDecode::Complete {
                record,
                body_offset,
            } => {
                let id = record.id;
                let timeout = record.timeout;
                let prefetched = buffer.split_off(body_offset);
                let env = OwnedEnvelope {
                    raw_header: buffer,
                    id,
                    timeout,
                };
                return Ok((env, FramedStream::new(stream, prefetched)));
            }
            PrefixDecode::Invalid => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid stream envelope header",
                ));
            }
            PrefixDecode::Incomplete => {
                if buffer.len() >= MAX_ENVELOPE_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "stream envelope header exceeds maximum size",
                    ));
                }
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stream ended inside its envelope header",
                    ));
                }
                buffer.extend_from_slice(&chunk[..n]);
            }
        }
    }
}

/// Reconstruct a [`FramedStream`] that replays `envelope.raw_header` ahead of any
/// prefetched body bytes, allowing a caller to fall back to a legacy stream handler
/// when [`OwnedEnvelope::component`] is not registered in [`crate::ComponentDirectory`].
pub fn rewind_envelope<S>(envelope: OwnedEnvelope, framed: FramedStream<S>) -> FramedStream<S> {
    let (stream, remaining_body) = framed.into_parts();
    let mut prefetched = envelope.raw_header;
    prefetched.extend_from_slice(&remaining_body);
    FramedStream::new(stream, prefetched)
}

/// Write a pre-encoded envelope header slice to `stream`.
pub async fn write_envelope<S>(stream: &mut S, encoded_header: &[u8]) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    stream.write_all(encoded_header).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_api::cbor::Encoder;

    #[tokio::test]
    async fn framed_stream_reads_envelope_once_and_preserves_prefetched_body() {
        let (mut client, server) = tokio::io::duplex(128);
        let mut hdr = [0u8; 64];
        let mut e = Encoder::new(&mut hdr);
        e.map(3).unwrap();
        e.str(b"component").unwrap();
        e.str(b"probe").unwrap();
        e.str(b"method").unwrap();
        e.str(b"handler").unwrap();
        e.str(b"id").unwrap();
        e.uint(77).unwrap();
        let hdr_len = e.len();

        let send = async move {
            // Write header + first part of body in a single write, then more body bytes.
            let mut combined = hdr[..hdr_len].to_vec();
            combined.extend_from_slice(b"hello ");
            client.write_all(&combined).await.unwrap();
            client.write_all(b"world\xff\xff").await.unwrap();
            client.shutdown().await.unwrap();
        };

        let recv = async move {
            let (env, mut framed) = read_envelope_prefix(server).await.unwrap();
            assert_eq!(env.id, Some(77));
            assert_eq!(env.component().unwrap().as_str(), Some("probe"));
            assert_eq!(env.method().unwrap().as_str(), Some("handler"));
            let mut body = Vec::new();
            framed.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, b"hello world\xff\xff");
        };

        tokio::join!(send, recv);
    }
}
