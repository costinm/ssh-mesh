use bytes::{Buf, Bytes, BytesMut};
use fastwebsockets::{Frame, OpCode, Payload, WebSocket};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tracing::{debug, error};

/// Bridge a WebSocket with an AsyncRead + AsyncWrite target
pub async fn bridge_ws<S, T>(mut ws: WebSocket<S>, mut target: T, label: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        tokio::select! {
            res = ws.read_frame() => {
                match res {
                    Ok(frame) => {
                        match frame.opcode {
                            OpCode::Binary | OpCode::Text => {
                                if target.write_all(&frame.payload).await.is_err() {
                                    break;
                                }
                            }
                            OpCode::Close => break,
                            _ => {}
                        }
                    }
                    Err(_) => break,
                }
            }
            res = target.read(&mut buf) => {
                match res {
                    Ok(0) => {
                        // EOF from target
                        let _ = ws.write_frame(Frame::close(1000, b"EOF")).await;
                        break;
                    }
                    Ok(n) => {
                        let frame = Frame::binary(Payload::Owned(buf[..n].to_vec()));
                        if ws.write_frame(frame).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    debug!("WebSocket bridge {} closed", label);
}

/// Bridge a WebSocket with MPSC channels
pub async fn bridge_ws_to_mpsc<S>(
    mut ws: WebSocket<S>,
    tx_to_mpsc: mpsc::UnboundedSender<Result<Bytes, std::io::Error>>,
    mut rx_from_mpsc: mpsc::UnboundedReceiver<Bytes>,
    label: &str,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            res = ws.read_frame() => {
                match res {
                    Ok(frame) => {
                        match frame.opcode {
                            OpCode::Binary | OpCode::Text => {
                                if tx_to_mpsc.send(Ok(Bytes::from(frame.payload.to_vec()))).is_err() {
                                    break;
                                }
                            }
                            OpCode::Close => break,
                            _ => {}
                        }
                    }
                    Err(e) => {
                        error!("WS bridge {}: read error: {}", label, e);
                        break;
                    }
                }
            }
            res = rx_from_mpsc.recv() => {
                match res {
                    Some(data) => {
                        let frame = Frame::binary(Payload::Owned(data.to_vec()));
                        if ws.write_frame(frame).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        let _ = ws.write_frame(Frame::close(1000, b"EOF")).await;
                        break;
                    }
                }
            }
        }
    }
    debug!("WebSocket MPSC bridge {} closed", label);
}

/// Pipe frames from WebSocket to an MPSC sender
pub async fn pipe_ws_to_tx<S>(mut ws: WebSocket<S>, tx: mpsc::Sender<Result<Bytes, std::io::Error>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    while let Ok(frame) = ws.read_frame().await {
        match frame.opcode {
            OpCode::Binary | OpCode::Text => {
                if tx
                    .send(Ok(Bytes::from(frame.payload.to_vec())))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            OpCode::Close => break,
            _ => {}
        }
    }
}

/// Pipe data from an MPSC receiver to a WebSocket as binary frames
pub async fn pipe_rx_to_ws<S>(mut ws: WebSocket<S>, mut rx: mpsc::Receiver<Bytes>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    while let Some(data) = rx.recv().await {
        let frame = Frame::binary(Payload::Owned(data.to_vec()));
        if ws.write_frame(frame).await.is_err() {
            break;
        }
    }
    let _ = ws.write_frame(Frame::close(1000, b"EOF")).await;
}

/// Adapter to bridge MPSC channels with AsyncRead + AsyncWrite
pub struct ChannelStream {
    pub reader: mpsc::Receiver<Result<Bytes, std::io::Error>>,
    pub writer: mpsc::Sender<Bytes>,
    pub read_buf: BytesMut,
}

impl AsyncRead for ChannelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.read_buf.is_empty() {
            let to_copy = buf.remaining().min(self.read_buf.len());
            buf.put_slice(&self.read_buf[..to_copy]);
            self.read_buf.advance(to_copy);
            return Poll::Ready(Ok(()));
        }

        match self.reader.poll_recv(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let to_copy = buf.remaining().min(data.len());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.read_buf.extend_from_slice(&data[to_copy..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ChannelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let data = Bytes::copy_from_slice(buf);
        match self.writer.try_send(data) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Adapter to bridge Unbounded MPSC channels with AsyncRead + AsyncWrite
pub struct UnboundedChannelStream {
    pub reader: mpsc::UnboundedReceiver<Result<Bytes, std::io::Error>>,
    pub writer: mpsc::UnboundedSender<Bytes>,
    pub read_buf: BytesMut,
}

impl AsyncRead for UnboundedChannelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.read_buf.is_empty() {
            let to_copy = buf.remaining().min(self.read_buf.len());
            buf.put_slice(&self.read_buf[..to_copy]);
            self.read_buf.advance(to_copy);
            return Poll::Ready(Ok(()));
        }

        match self.reader.poll_recv(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let to_copy = buf.remaining().min(data.len());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.read_buf.extend_from_slice(&data[to_copy..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for UnboundedChannelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let data = Bytes::copy_from_slice(buf);
        if self.writer.send(data).is_err() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Channel closed",
            )));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Bridge two bidirectional streams
pub async fn bridge<S1, S2>(mut s1: S1, mut s2: S2, label: &str)
where
    S1: AsyncRead + AsyncWrite + Unpin,
    S2: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::io::copy_bidirectional(&mut s1, &mut s2).await {
        Ok((from_s1, from_s2)) => {
            debug!(
                "Bridge {} completed: {} bytes in, {} bytes out",
                label, from_s1, from_s2
            );
        }
        Err(e) => {
            if e.kind() != std::io::ErrorKind::BrokenPipe {
                debug!("Bridge {} error: {}", label, e);
            }
        }
    }
}

/// Pipe data from an AsyncRead to an SSH channel
pub async fn pipe_read_to_ssh<R>(
    mut reader: R,
    session_handle: russh::server::Handle,
    channel_id: russh::ChannelId,
    label: &str,
) where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                debug!("{} EOF", label);
                break;
            }
            Ok(n) => {
                if session_handle
                    .data(channel_id, (&buf[..n]).into())
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Other || e.raw_os_error() == Some(5) => {
                // Handle PTY EIO or other "expected" closures
                debug!("{} closed cleanly: {}", label, e);
                break;
            }
            Err(e) => {
                error!("{} read error: {}", label, e);
                break;
            }
        }
    }
    let _ = session_handle.close(channel_id).await;
}

/// Pipe data from an MPSC receiver to an AsyncWrite
pub async fn pipe_rx_to_write<W>(mut rx: mpsc::UnboundedReceiver<Bytes>, mut writer: W, label: &str)
where
    W: AsyncWrite + Unpin,
{
    while let Some(data) = rx.recv().await {
        if writer.write_all(&data).await.is_err() {
            break;
        }
        if writer.flush().await.is_err() {
            break;
        }
    }
    debug!("{} receiver closed", label);
}

/// Pipe data from an AsyncRead to an SSH channel as extended data
pub async fn pipe_read_to_ssh_extended<R>(
    mut reader: R,
    session_handle: russh::server::Handle,
    channel_id: russh::ChannelId,
    ext: u32,
    label: &str,
) where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if session_handle
                    .extended_data(channel_id, ext, (&buf[..n]).into())
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(e) => {
                error!("{} read error: {}", label, e);
                break;
            }
        }
    }
    debug!("{} EOF", label);
}
