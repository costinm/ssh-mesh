//! User-facing `tokio` session and stream APIs for `quic-mux`, providing **both**:
//!
//! 1. **Traditional TCP-substitute byte streams ([`MuxStream`], [`MuxReadHalf`], [`MuxWriteHalf`]):**
//!    Implements [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`] + `Unpin` + `Send` + `Sync`,
//!    usable as a drop-in replacement for `tokio::net::TcpStream` / `UnixStream` with
//!    `tokio::io::copy_bidirectional`, `AsyncReadExt`, `AsyncWriteExt`, `russh`, `hyper`, etc.
//! 2. **Zero-copy packet pool ownership passing ([`MuxStream::alloc_packet`], [`MuxStream::send_packet`],
//!    [`MuxStream::recv_chunk`], [`OwnedRxChunk`]):**
//!    Transfers exclusive `XipLazyPacket` ownership (`refs == 1`) directly between links, handlers,
//!    and outbound streams with zero payload copies and RAII end-to-end flow-control credit release.
//!
//! Both APIs share the exact same [`MuxStream`] type (and split halves) and can even be mixed on a
//! single stream — for example reading a small routing header via `AsyncReadExt::read_exact` and
//! then splicing the remaining body zero-copy via `recv_chunk` + `send_packet`.

use std::boxed::Box;
use std::collections::{BTreeMap, VecDeque};
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use std::vec::Vec;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixDatagram, UnixStream};
use tokio::sync::Notify;

use crate::flow::{
    AssociationBrokenReason, MuxCallbacks, RxOutcome, StreamCloseReason, StreamError,
    StreamPriority,
};
use crate::link::{AssociationId, RxMeta};
use crate::mux::{MuxError, MuxLimits, MuxSendError, QuicMux};
use crate::pool::{
    PacketPool, PoolError, PoolPacket, XipLazyPacket, XipLazyPool,
};
use crate::streams::{RxStreamChunk, TxStreamData};
use crate::tokio_mux::{TokioLinkSet, TokioRxPacket};
use crate::wire::StreamId;

/// Default `AssociationId` used by single-association `TokioMux` helpers.
pub const DEFAULT_ASSOCIATION_ID: AssociationId = AssociationId(1);

/// Configuration for [`TokioMux`].
#[derive(Clone)]
pub struct TokioMuxConfig {
    /// Shared packet pool used for zero-copy RX/TX framing across all attached links.
    pub pool: XipLazyPool,
    /// `QuicMux` flow-control and resource pressure limits.
    pub limits: MuxLimits,
    /// Inbound packet channel capacity between link readers and the mux pump.
    pub rx_channel_capacity: usize,
    /// Default per-link TX ring capacity (in packets).
    pub default_tx_ring_capacity: usize,
    /// Minimum pool slots kept reserved for inbound RX frames (`MAX_DATA`, `STREAM`, etc.)
    /// so TX saturation can never starve RX progress.
    pub rx_reserve_slots: usize,
}

impl Default for TokioMuxConfig {
    fn default() -> Self {
        let pool = XipLazyPool::with_default_geometry(128);
        pool.set_keep(64);
        let limits = MuxLimits {
            initial_max_data: 64 * 1024,
            initial_max_stream_data: 16 * 1024,
            initial_max_streams_bidi: 64,
            initial_max_streams_uni: 64,
            max_concurrent_streams: 64,
            max_queued_chunks_per_stream: 64,
            max_association_rx_packets: 256,
            max_device_rx_packets: 256,
            gap_timeout_us: 3_000_000,
        };
        Self {
            pool,
            limits,
            rx_channel_capacity: 128,
            default_tx_ring_capacity: 32,
            rx_reserve_slots: 8,
        }
    }
}

enum RxPayload {
    Packet(XipLazyPacket),
    Small { data: Box<[u8]>, start: usize },
}

impl RxPayload {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Packet(pkt) => pkt.bytes(),
            Self::Small { data, start } => &data[*start..],
        }
    }

    fn trim_prefix(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        match self {
            Self::Packet(pkt) => {
                let r = pkt.range();
                let _ = pkt.set_range((r.start + n).min(r.end)..r.end);
            }
            Self::Small { data, start } => {
                *start = (*start + n).min(data.len());
            }
        }
    }
}

struct QueuedRxItem {
    payload: RxPayload,
    credit_bytes: usize,
    fin: bool,
}

/// Zero-copy RX chunk yielded by [`MuxStream::recv_chunk`] and [`MuxReadHalf::recv_chunk`].
///
/// - For single-stream packets and for the `> 1/2 MTU` frame in a multi-frame packet,
///   [`Self::take_packet`] returns `Some(XipLazyPacket)` with `is_unique() == true`, ready to be
///   passed directly to [`MuxStream::send_packet`] on another stream with zero payload copies.
/// - For small (`<= 1/2 MTU`) frames extracted from a multi-frame packet, [`Self::take_packet`]
///   returns `None` and [`Self::bytes`] exposes the compact small buffer slice.
/// - Dropping [`OwnedRxChunk`] automatically releases its `MAX_STREAM_DATA` and `MAX_DATA`
///   flow-control credit back to the peer, providing end-to-end backpressure across proxy hops.
pub struct OwnedRxChunk {
    payload: Option<RxPayload>,
    fin: bool,
    assoc: AssociationId,
    stream_id: StreamId,
    unreleased_credit: usize,
    core: Option<Arc<Mutex<MuxCore>>>,
}

impl OwnedRxChunk {
    fn new(
        item: QueuedRxItem,
        assoc: AssociationId,
        stream_id: StreamId,
        core: Arc<Mutex<MuxCore>>,
    ) -> Self {
        Self {
            payload: Some(item.payload),
            fin: item.fin,
            assoc,
            stream_id,
            unreleased_credit: item.credit_bytes,
            core: Some(core),
        }
    }

    /// Active payload bytes (`&[]` if [`Self::take_packet`] was already called).
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        match &self.payload {
            Some(p) => p.bytes(),
            None => &[],
        }
    }

    /// Length of the remaining payload slice in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes().len()
    }

    /// Whether the payload slice is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether this chunk carries the stream's `FIN` (end-of-stream) marker.
    #[inline]
    pub const fn is_fin(&self) -> bool {
        self.fin
    }

    /// Whether this chunk owns an underlying `XipLazyPacket` from the pool (`true` for single-stream
    /// packets and for `> 1/2 MTU` frames in multi-frame packets).
    #[inline]
    pub const fn is_packet_owned(&self) -> bool {
        matches!(self.payload, Some(RxPayload::Packet(_)))
    }

    /// Take exclusive ownership of the underlying `XipLazyPacket`, if backed by a pool packet.
    ///
    /// Receive flow-control credit remains held until this `OwnedRxChunk` is dropped (or
    /// [`Self::release_credit_now`] is called), preserving backpressure while forwarding.
    #[inline]
    pub fn take_packet(&mut self) -> Option<XipLazyPacket> {
        if matches!(self.payload, Some(RxPayload::Packet(_))) {
            if let Some(RxPayload::Packet(pkt)) = self.payload.take() {
                return Some(pkt);
            }
        }
        None
    }

    /// Explicitly release receive flow-control credit immediately before dropping `self`.
    pub fn release_credit_now(&mut self) {
        if self.unreleased_credit > 0 {
            let bytes = self.unreleased_credit;
            self.unreleased_credit = 0;
            if let Some(core) = self.core.take() {
                if let Ok(mut guard) = core.lock() {
                    let wakers = guard.on_credit_released(self.assoc, self.stream_id, bytes);
                    drop(guard);
                    for w in wakers {
                        w.wake();
                    }
                }
            }
        }
    }

    fn trim_prefix(&mut self, n: usize) {
        if let Some(p) = &mut self.payload {
            p.trim_prefix(n);
        }
    }
}

impl Drop for OwnedRxChunk {
    fn drop(&mut self) {
        // Release pool packet slot first so `flush_control` or local writers can reuse the warm slot.
        let freed_pool_slot = matches!(self.payload.take(), Some(RxPayload::Packet(_)));
        let bytes = self.unreleased_credit;
        self.unreleased_credit = 0;
        if bytes > 0 || freed_pool_slot {
            if let Some(core) = self.core.take() {
                if let Ok(mut guard) = core.lock() {
                    let wakers = guard.on_credit_released(self.assoc, self.stream_id, bytes);
                    drop(guard);
                    for w in wakers {
                        w.wake();
                    }
                }
            }
        }
    }
}

struct StreamEndpointState {
    rx_queue: VecDeque<QueuedRxItem>,
    fin_queued: bool,
    local_fin_sent: bool,
    locally_reset: bool,
    rx_error: Option<StreamCloseReason>,
    tx_error: Option<StreamCloseReason>,
    read_dropped: bool,
    write_dropped: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl StreamEndpointState {
    fn new() -> Self {
        Self {
            rx_queue: VecDeque::new(),
            fin_queued: false,
            local_fin_sent: false,
            locally_reset: false,
            rx_error: None,
            tx_error: None,
            read_dropped: false,
            write_dropped: false,
            read_waker: None,
            write_waker: None,
        }
    }
}

struct HandleLifecycle {
    active_handles: AtomicUsize,
    mux_handles: AtomicUsize,
    shutdown_notify: Notify,
}

impl HandleLifecycle {
    fn inc(&self) {
        self.active_handles.fetch_add(1, Ordering::Relaxed);
    }

    fn dec(&self) {
        if self.active_handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shutdown_notify.notify_waiters();
        }
    }

    fn inc_mux(&self) {
        self.active_handles.fetch_add(1, Ordering::Relaxed);
        self.mux_handles.fetch_add(1, Ordering::Relaxed);
    }

    fn dec_mux(&self) {
        let last_mux = self.mux_handles.fetch_sub(1, Ordering::AcqRel) == 1;
        let last_handle = self.active_handles.fetch_sub(1, Ordering::AcqRel) == 1;
        if last_mux || last_handle {
            self.shutdown_notify.notify_waiters();
        }
    }
}

struct MuxCore {
    mux: QuicMux<XipLazyPool>,
    links: TokioLinkSet,
    default_assoc: AssociationId,
    default_tx_ring_capacity: usize,
    start_instant: Instant,
    assoc_roles: BTreeMap<AssociationId, bool>,
    broken_assocs: Vec<AssociationId>,
    streams: BTreeMap<(AssociationId, StreamId), StreamEndpointState>,
    pending_fins: VecDeque<(AssociationId, StreamId)>,
    accept_queue: VecDeque<(AssociationId, StreamId)>,
    accept_waker: Option<Waker>,
    open_wakers: Vec<Waker>,
    closed: bool,
}

impl MuxCore {
    #[inline]
    fn now_us(&self) -> u64 {
        u64::try_from(self.start_instant.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    fn on_credit_released(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Vec<Waker> {
        if bytes > 0 {
            let _ = self
                .mux
                .release_stream_credit(assoc, stream_id, bytes, &mut self.links);
        }
        self.maybe_gc_stream(assoc, stream_id);
        let mut wakers = Vec::new();
        for ep in self.streams.values_mut() {
            if let Some(w) = ep.write_waker.take() {
                wakers.push(w);
            }
        }
        wakers
    }

    fn maybe_gc_stream(&mut self, assoc: AssociationId, stream_id: StreamId) {
        let should_remove = match self.streams.get(&(assoc, stream_id)) {
            Some(ep) => {
                ep.read_dropped
                    && ep.write_dropped
                    && ep.rx_queue.is_empty()
                    && (ep.local_fin_sent || ep.locally_reset || ep.tx_error.is_some())
                    && (ep.fin_queued || ep.locally_reset || ep.rx_error.is_some())
            }
            None => false,
        };
        if should_remove {
            self.streams.remove(&(assoc, stream_id));
            self.mux.close_stream(assoc, stream_id, &mut self.links);
        }
    }

    fn flush_pending_work(&mut self, wakers: &mut Vec<Waker>) {
        // Retry any deferred FINs from dropped write halves.
        let mut remaining_fins = VecDeque::new();
        while let Some((assoc, sid)) = self.pending_fins.pop_front() {
            let still_needed = self
                .streams
                .get(&(assoc, sid))
                .is_some_and(|ep| !ep.local_fin_sent && !ep.locally_reset && ep.tx_error.is_none());
            if !still_needed {
                self.maybe_gc_stream(assoc, sid);
                continue;
            }
            match self.mux.write_stream(
                assoc,
                sid,
                TxStreamData::Bytes(&[]),
                true,
                &mut self.links,
            ) {
                Ok(_)
                | Err(MuxSendError::Error {
                    error:
                        MuxError::StreamFinished
                        | MuxError::UnknownStream
                        | MuxError::StreamReset
                        | MuxError::InvalidStreamState,
                    ..
                }) => {
                    if let Some(ep) = self.streams.get_mut(&(assoc, sid)) {
                        ep.local_fin_sent = true;
                    }
                    self.maybe_gc_stream(assoc, sid);
                }
                Err(MuxSendError::Busy(_))
                | Err(MuxSendError::FlowControl(_))
                | Err(MuxSendError::Error {
                    error: MuxError::Pool(PoolError::Exhausted),
                    ..
                }) => {
                    remaining_fins.push_back((assoc, sid));
                }
                Err(_) => {
                    if let Some(ep) = self.streams.get_mut(&(assoc, sid)) {
                        ep.locally_reset = true;
                    }
                    self.maybe_gc_stream(assoc, sid);
                }
            }
        }
        self.pending_fins = remaining_fins;

        let assocs: Vec<AssociationId> = self.assoc_roles.keys().copied().collect();
        for assoc in assocs {
            let _ = self.mux.flush_control(assoc, &mut self.links);
        }

        // Wake any writers waiting on TX ring space, pool slots, or flush completion.
        for ep in self.streams.values_mut() {
            if let Some(w) = ep.write_waker.take() {
                wakers.push(w);
            }
        }
        wakers.append(&mut self.open_wakers);
    }

    fn ingest_rx_packet(&mut self, pkt: TokioRxPacket, wakers: &mut Vec<Waker>) {
        if pkt.association.0 != 0
            && !self.assoc_roles.contains_key(&pkt.association)
            && self.assoc_roles.get(&self.default_assoc) == Some(&false)
        {
            if self.mux.add_association(pkt.association, false).is_ok() {
                self.assoc_roles.insert(pkt.association, false);
            }
        }
        let now_us = self.now_us();
        let MuxCore {
            mux,
            links,
            assoc_roles,
            broken_assocs,
            streams,
            accept_queue,
            accept_waker,
            open_wakers,
            ..
        } = self;
        let mut cb = DispatcherCallbacks {
            assoc_roles,
            broken_assocs,
            streams,
            accept_queue,
            accept_waker,
            open_wakers,
            wakers_out: wakers,
        };
        let _ = mux.receive_packet(
            RxMeta {
                association: pkt.association,
                received_at_us: now_us,
            },
            pkt.packet,
            links,
            &mut cb,
        );
        self.reset_broken_associations(wakers);
    }

    fn reset_broken_associations(&mut self, wakers: &mut Vec<Waker>) {
        while let Some(assoc) = self.broken_assocs.pop() {
            let is_client = self.assoc_roles.get(&assoc).copied().unwrap_or(false);
            let MuxCore {
                mux,
                assoc_roles,
                broken_assocs,
                streams,
                accept_queue,
                accept_waker,
                open_wakers,
                ..
            } = self;
            let mut cb = DispatcherCallbacks {
                assoc_roles,
                broken_assocs,
                streams,
                accept_queue,
                accept_waker,
                open_wakers,
                wakers_out: wakers,
            };
            mux.remove_association(assoc, &mut cb);
            let _ = self.mux.add_association(assoc, is_client);
        }
    }

    fn mark_session_closed(&mut self, wakers: &mut Vec<Waker>) {
        self.closed = true;
        self.links.close_all();
        if let Some(w) = self.accept_waker.take() {
            wakers.push(w);
        }
        for ep in self.streams.values_mut() {
            if !ep.fin_queued && ep.rx_error.is_none() {
                ep.rx_error = Some(StreamCloseReason::AssociationClosed {
                    delivered_offset: 0,
                });
            }
            if !ep.local_fin_sent && ep.tx_error.is_none() {
                ep.tx_error = Some(StreamCloseReason::AssociationClosed {
                    delivered_offset: 0,
                });
            }
            if let Some(w) = ep.read_waker.take() {
                wakers.push(w);
            }
            if let Some(w) = ep.write_waker.take() {
                wakers.push(w);
            }
        }
        wakers.append(&mut self.open_wakers);
    }
}

struct DispatcherCallbacks<'a> {
    assoc_roles: &'a BTreeMap<AssociationId, bool>,
    broken_assocs: &'a mut Vec<AssociationId>,
    streams: &'a mut BTreeMap<(AssociationId, StreamId), StreamEndpointState>,
    accept_queue: &'a mut VecDeque<(AssociationId, StreamId)>,
    accept_waker: &'a mut Option<Waker>,
    open_wakers: &'a mut Vec<Waker>,
    wakers_out: &'a mut Vec<Waker>,
}

impl MuxCallbacks<XipLazyPacket> for DispatcherCallbacks<'_> {
    fn on_stream_data(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        _offset: u64,
        mut chunk: RxStreamChunk<'_, XipLazyPacket>,
        fin: bool,
    ) -> Result<RxOutcome<XipLazyPacket>, StreamError> {
        let is_client = self.assoc_roles.get(&assoc).copied().unwrap_or(true);
        let is_peer_initiated = stream_id.is_client_initiated() != is_client;

        if !self.streams.contains_key(&(assoc, stream_id)) {
            if !is_peer_initiated {
                // Late data for an already closed local stream; consume and release immediately.
                return Ok(RxOutcome::Consumed(chunk.len()));
            }
            let mut ep = StreamEndpointState::new();
            if stream_id.is_uni() {
                // Peer-initiated unidirectional stream has no local write half.
                ep.local_fin_sent = true;
            }
            self.streams.insert((assoc, stream_id), ep);
            self.accept_queue.push_back((assoc, stream_id));
            if let Some(w) = self.accept_waker.take() {
                self.wakers_out.push(w);
            }
        }

        let ep = self.streams.get_mut(&(assoc, stream_id)).unwrap();
        let len = chunk.len();

        if ep.read_dropped {
            if fin {
                ep.fin_queued = true;
            }
            return Ok(RxOutcome::Consumed(len));
        }

        if len == 0 {
            if fin {
                ep.fin_queued = true;
                if let Some(back) = ep.rx_queue.back_mut() {
                    back.fin = true;
                }
                if let Some(w) = ep.read_waker.take() {
                    self.wakers_out.push(w);
                }
            }
            return Ok(RxOutcome::Consumed(0));
        }

        let payload = match chunk.take_packet() {
            Some(pkt) => RxPayload::Packet(pkt),
            None => RxPayload::Small {
                data: Box::from(chunk.small_buf),
                start: 0,
            },
        };
        ep.rx_queue.push_back(QueuedRxItem {
            payload,
            credit_bytes: len,
            fin,
        });
        if fin {
            ep.fin_queued = true;
        }
        if let Some(w) = ep.read_waker.take() {
            self.wakers_out.push(w);
        }
        Ok(RxOutcome::RetainedPendingCredit)
    }

    fn on_stream_closed(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        reason: StreamCloseReason,
    ) {
        let Some(ep) = self.streams.get_mut(&(assoc, stream_id)) else {
            return;
        };
        match reason {
            StreamCloseReason::PeerStopSending { .. } => {
                ep.tx_error = Some(reason);
                if let Some(w) = ep.write_waker.take() {
                    self.wakers_out.push(w);
                }
            }
            StreamCloseReason::PeerReset { .. } => {
                ep.rx_error = Some(reason);
                ep.rx_queue.clear();
                if let Some(w) = ep.read_waker.take() {
                    self.wakers_out.push(w);
                }
            }
            StreamCloseReason::GapTimeout { .. }
            | StreamCloseReason::ResourcePressure { .. }
            | StreamCloseReason::AssociationClosed { .. } => {
                ep.rx_error = Some(reason);
                ep.tx_error = Some(reason);
                ep.rx_queue.clear();
                if let Some(w) = ep.read_waker.take() {
                    self.wakers_out.push(w);
                }
                if let Some(w) = ep.write_waker.take() {
                    self.wakers_out.push(w);
                }
            }
        }
        self.wakers_out.append(self.open_wakers);
    }

    fn on_association_broken(&mut self, assoc: AssociationId, reason: AssociationBrokenReason) {
        if !self.broken_assocs.contains(&assoc) {
            self.broken_assocs.push(assoc);
        }
        let close_reason = match reason {
            AssociationBrokenReason::StreamGapTimeout { missing_offset, .. } => {
                StreamCloseReason::GapTimeout { missing_offset }
            }
            AssociationBrokenReason::PeerConnectionClose { .. } => {
                StreamCloseReason::AssociationClosed {
                    delivered_offset: 0,
                }
            }
        };
        for (&(aid, _sid), ep) in self.streams.iter_mut() {
            if aid == assoc {
                if ep.rx_error.is_none() {
                    ep.rx_error = Some(close_reason);
                }
                if ep.tx_error.is_none() {
                    ep.tx_error = Some(close_reason);
                }
                if let Some(w) = ep.read_waker.take() {
                    self.wakers_out.push(w);
                }
                if let Some(w) = ep.write_waker.take() {
                    self.wakers_out.push(w);
                }
            }
        }
    }

    fn on_stream_writable(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        _writable_bytes: usize,
    ) {
        if let Some(ep) = self.streams.get_mut(&(assoc, stream_id)) {
            if let Some(w) = ep.write_waker.take() {
                self.wakers_out.push(w);
            }
        }
    }

    fn on_association_writable(&mut self, assoc: AssociationId, _association_window: u64) {
        for (&(aid, _), ep) in self.streams.iter_mut() {
            if aid == assoc {
                if let Some(w) = ep.write_waker.take() {
                    self.wakers_out.push(w);
                }
            }
        }
        self.wakers_out.append(self.open_wakers);
    }

    fn on_device_writable(&mut self) {
        for ep in self.streams.values_mut() {
            if let Some(w) = ep.write_waker.take() {
                self.wakers_out.push(w);
            }
        }
        self.wakers_out.append(self.open_wakers);
    }
}

fn close_reason_to_io_error(reason: StreamCloseReason) -> io::Error {
    match reason {
        StreamCloseReason::PeerReset { error_code, .. } => io::Error::new(
            io::ErrorKind::ConnectionReset,
            alloc::format!("peer reset stream (code {error_code})"),
        ),
        StreamCloseReason::PeerStopSending { error_code } => io::Error::new(
            io::ErrorKind::BrokenPipe,
            alloc::format!("peer stopped reading stream (code {error_code})"),
        ),
        StreamCloseReason::GapTimeout { missing_offset } => io::Error::new(
            io::ErrorKind::TimedOut,
            alloc::format!("missing frame gap timed out at offset {missing_offset}"),
        ),
        StreamCloseReason::ResourcePressure { .. } => io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "stream reset due to resource pressure",
        ),
        StreamCloseReason::AssociationClosed { .. } => io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "underlying association closed",
        ),
    }
}

/// Clonable handle to a running `tokio` `quic-mux` session.
///
/// Can open streams (`MuxStream`) concurrently from multiple tasks and dynamically attach
/// single or multipath TCP (`TcpStream`), UDS stream (`UnixStream`), or UDS datagram
/// (`UnixDatagram`) links.
pub struct TokioMux {
    core: Arc<Mutex<MuxCore>>,
    pool: XipLazyPool,
    rx_reserve_slots: usize,
    lifecycle: Arc<HandleLifecycle>,
}

impl Clone for TokioMux {
    fn clone(&self) -> Self {
        self.lifecycle.inc_mux();
        Self {
            core: self.core.clone(),
            pool: self.pool.clone(),
            rx_reserve_slots: self.rx_reserve_slots,
            lifecycle: self.lifecycle.clone(),
        }
    }
}

impl Drop for TokioMux {
    fn drop(&mut self) {
        self.lifecycle.dec_mux();
    }
}

/// Listener accepting peer-initiated [`MuxStream`]s (analogous to `tokio::net::TcpListener`).
pub struct TokioMuxAcceptor {
    core: Arc<Mutex<MuxCore>>,
    pool: XipLazyPool,
    rx_reserve_slots: usize,
    lifecycle: Arc<HandleLifecycle>,
}

impl Drop for TokioMuxAcceptor {
    fn drop(&mut self) {
        {
            if let Ok(mut guard) = self.core.lock() {
                let core = &mut *guard;
                core.accept_waker = None;
                // Clean up any unaccepted streams queued before the acceptor was dropped.
                while let Some((assoc, sid)) = core.accept_queue.pop_front() {
                    if let Some(mut ep) = core.streams.remove(&(assoc, sid)) {
                        ep.rx_queue.clear();
                    }
                    core.mux.reset_stream(assoc, sid, 0, &mut core.links);
                }
            }
        }
        self.lifecycle.dec();
    }
}

impl TokioMuxAcceptor {
    /// Accept the next peer-initiated [`MuxStream`], returning `None` when the mux session closes.
    pub async fn accept(&mut self) -> Option<MuxStream> {
        poll_fn(|cx| {
            let mut guard = self.core.lock().unwrap();
            while let Some((assoc, sid)) = guard.accept_queue.pop_front() {
                if guard.streams.contains_key(&(assoc, sid)) {
                    drop(guard);
                    return Poll::Ready(Some(MuxStream::from_parts(
                        assoc,
                        sid,
                        self.core.clone(),
                        self.pool.clone(),
                        self.rx_reserve_slots,
                        self.lifecycle.clone(),
                    )));
                }
            }
            if guard.closed {
                return Poll::Ready(None);
            }
            guard.accept_waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

impl TokioMux {
    /// Spawn a new `TokioMux` session with `DEFAULT_ASSOCIATION_ID` (`AssociationId(1)`) registered
    /// in role `is_client` (`true` = client, `false` = server).
    ///
    /// Links can be attached before or after opening streams via [`Self::add_tcp_link`],
    /// [`Self::add_uds_stream_link`], [`Self::add_stream_link`], or [`Self::add_datagram_link`].
    pub fn spawn(is_client: bool, config: TokioMuxConfig) -> (Self, TokioMuxAcceptor) {
        let pool = config.pool;
        let rx_reserve = config
            .rx_reserve_slots
            .min(usize::from(pool.slots()).saturating_sub(2));
        let mut mux = QuicMux::new(pool.clone(), config.limits);
        let default_assoc = DEFAULT_ASSOCIATION_ID;
        mux.add_association(default_assoc, is_client)
            .expect("fresh QuicMux accepts initial association");

        let mut links = TokioLinkSet::new(pool.clone(), config.rx_channel_capacity);
        let mut rx_rx = links
            .take_rx_receiver()
            .expect("fresh TokioLinkSet has rx receiver");
        let tx_space_notify = links.tx_space_notify();

        let mut assoc_roles = BTreeMap::new();
        assoc_roles.insert(default_assoc, is_client);

        let core = Arc::new(Mutex::new(MuxCore {
            mux,
            links,
            default_assoc,
            default_tx_ring_capacity: config.default_tx_ring_capacity.max(1),
            start_instant: Instant::now(),
            assoc_roles,
            broken_assocs: Vec::new(),
            streams: BTreeMap::new(),
            pending_fins: VecDeque::new(),
            accept_queue: VecDeque::new(),
            accept_waker: None,
            open_wakers: Vec::new(),
            closed: false,
        }));

        // 2 initial handles: `TokioMux` + `TokioMuxAcceptor`.
        let lifecycle = Arc::new(HandleLifecycle {
            active_handles: AtomicUsize::new(2),
            mux_handles: AtomicUsize::new(1),
            shutdown_notify: Notify::new(),
        });

        let core_pump = core.clone();
        let lifecycle_pump = lifecycle.clone();
        tokio::spawn(async move {
            let mut wakers = Vec::with_capacity(16);
            loop {
                let shutdown_notified = lifecycle_pump.shutdown_notify.notified();
                tokio::pin!(shutdown_notified);
                shutdown_notified.as_mut().enable();

                let tx_notified = tx_space_notify.notified();
                tokio::pin!(tx_notified);
                tx_notified.as_mut().enable();

                let (should_exit, next_sleep_dur) = {
                    let mut guard = core_pump.lock().unwrap();
                    // Drain any packets already buffered in `rx_rx` before evaluating link EOF
                    // so final data/FIN frames read right before peer disconnect are delivered.
                    while let Ok(pkt) = rx_rx.try_recv() {
                        guard.ingest_rx_packet(pkt, &mut wakers);
                    }
                    guard.flush_pending_work(&mut wakers);
                    let no_handles =
                        lifecycle_pump.active_handles.load(Ordering::Acquire) == 0;
                    let no_mux_handles =
                        lifecycle_pump.mux_handles.load(Ordering::Acquire) == 0;
                    let all_flushed = guard
                        .assoc_roles
                        .keys()
                        .all(|&a| guard.links.is_assoc_flushed(a));
                    let links_eof = guard.links.all_links_closed();
                    let unattached_dead = no_mux_handles && !guard.links.has_links();
                    if guard.closed
                        || links_eof
                        || unattached_dead
                        || (no_handles && guard.pending_fins.is_empty() && all_flushed)
                    {
                        guard.mark_session_closed(&mut wakers);
                        (true, None)
                    } else {
                        let now = guard.now_us();
                        let sleep_dur = guard.mux.next_deadline().map(|dl| {
                            Duration::from_micros(dl.saturating_sub(now))
                        });
                        (false, sleep_dur)
                    }
                };
                for w in wakers.drain(..) {
                    w.wake();
                }
                if should_exit {
                    break;
                }

                tokio::select! {
                    biased;
                    maybe_pkt = rx_rx.recv() => {
                        let Some(first_pkt) = maybe_pkt else {
                            let mut guard = core_pump.lock().unwrap();
                            guard.mark_session_closed(&mut wakers);
                            drop(guard);
                            for w in wakers.drain(..) { w.wake(); }
                            break;
                        };

                        {
                            let mut guard = core_pump.lock().unwrap();
                            let mut pkt = first_pkt;
                            let mut batch = 0usize;
                            loop {
                                guard.ingest_rx_packet(pkt, &mut wakers);
                                batch += 1;
                                if batch >= 32 {
                                    break;
                                }
                                match rx_rx.try_recv() {
                                    Ok(next) => pkt = next,
                                    Err(_) => break,
                                }
                            }
                            guard.flush_pending_work(&mut wakers);
                        }
                        for w in wakers.drain(..) {
                            w.wake();
                        }
                    }
                    _ = tx_notified => {
                        {
                            let mut guard = core_pump.lock().unwrap();
                            guard.flush_pending_work(&mut wakers);
                        }
                        for w in wakers.drain(..) {
                            w.wake();
                        }
                    }
                    _ = async {
                        match next_sleep_dur {
                            Some(d) => tokio::time::sleep(d).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        {
                            let mut guard = core_pump.lock().unwrap();
                            let now_us = guard.now_us();
                            let MuxCore {
                                mux,
                                links,
                                assoc_roles,
                                broken_assocs,
                                streams,
                                accept_queue,
                                accept_waker,
                                open_wakers,
                                ..
                            } = &mut *guard;
                            let mut cb = DispatcherCallbacks {
                                assoc_roles,
                                broken_assocs,
                                streams,
                                accept_queue,
                                accept_waker,
                                open_wakers,
                                wakers_out: &mut wakers,
                            };
                            mux.advance_time(now_us, links, &mut cb);
                            guard.reset_broken_associations(&mut wakers);
                        }
                        for w in wakers.drain(..) {
                            w.wake();
                        }
                    }
                    _ = shutdown_notified => {}
                }
            }
        });

        let handle = Self {
            core: core.clone(),
            pool: pool.clone(),
            rx_reserve_slots: rx_reserve,
            lifecycle: lifecycle.clone(),
        };
        let acceptor = TokioMuxAcceptor {
            core,
            pool,
            rx_reserve_slots: rx_reserve,
            lifecycle,
        };
        (handle, acceptor)
    }

    /// Create a client `TokioMux` over a single byte-stream (`TcpStream`, `UnixStream`, TLS, etc.).
    pub fn client<S>(stream: S, config: TokioMuxConfig) -> (Self, TokioMuxAcceptor)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (mux, acceptor) = Self::spawn(true, config);
        mux.add_stream_link(stream, 10);
        (mux, acceptor)
    }

    /// Create a server `TokioMux` over a single byte-stream (`TcpStream`, `UnixStream`, TLS, etc.).
    pub fn server<S>(stream: S, config: TokioMuxConfig) -> (Self, TokioMuxAcceptor)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (mux, acceptor) = Self::spawn(false, config);
        mux.add_stream_link(stream, 10);
        (mux, acceptor)
    }

    /// Send an application `CONNECTION_CLOSE` (`0x1d`) frame on all active associations so a
    /// peer sharing a persistent packet link (such as PPP serial) resets its association state.
    pub fn send_connection_close(&self, error_code: u64) {
        let mut guard = self.core.lock().unwrap();
        let MuxCore {
            mux,
            links,
            assoc_roles,
            ..
        } = &mut *guard;
        for &assoc in assoc_roles.keys() {
            let _ = mux.close_association(assoc, true, error_code, 0, links);
        }
    }

    /// Returns `true` once all attached links have drained their outbound TX queues.
    pub fn is_flushed(&self) -> bool {
        let guard = self.core.lock().unwrap();
        guard
            .assoc_roles
            .keys()
            .all(|&a| guard.links.is_assoc_flushed(a))
    }

    /// Explicitly close this mux session, detaching all links and waking any pending
    /// `TokioMuxAcceptor::accept` or stream operations.
    pub fn close(&self) {
        let mut wakers = Vec::new();
        {
            let mut guard = self.core.lock().unwrap();
            guard.mark_session_closed(&mut wakers);
        }
        for w in wakers {
            w.wake();
        }
        self.lifecycle.shutdown_notify.notify_waiters();
    }

    /// Override the default association ID used by [`Self::open_bidi`], [`Self::open_uni`],
    /// and the default `add_*_link` helpers (registering `assoc` if not already present).
    pub fn set_default_association(
        &self,
        assoc: AssociationId,
        is_client: bool,
    ) -> Result<(), MuxError> {
        let mut guard = self.core.lock().unwrap();
        if !guard.assoc_roles.contains_key(&assoc) {
            guard.mux.add_association(assoc, is_client)?;
            guard.assoc_roles.insert(assoc, is_client);
        }
        guard.default_assoc = assoc;
        Ok(())
    }

    /// Register an additional association ID on this mux.
    pub fn add_association(&self, assoc: AssociationId, is_client: bool) -> Result<(), MuxError> {
        let mut guard = self.core.lock().unwrap();
        guard.mux.add_association(assoc, is_client)?;
        guard.assoc_roles.insert(assoc, is_client);
        Ok(())
    }

    /// Attach a `TcpStream` link to the default association with `cost`.
    pub fn add_tcp_link(&self, stream: TcpStream, cost: u16) {
        let mut guard = self.core.lock().unwrap();
        let assoc = guard.default_assoc;
        let cap = guard.default_tx_ring_capacity;
        guard.links.add_tcp_link(assoc, stream, cost, cap);
    }

    /// Attach a `UnixStream` link to the default association with `cost`.
    pub fn add_uds_stream_link(&self, stream: UnixStream, cost: u16) {
        let mut guard = self.core.lock().unwrap();
        let assoc = guard.default_assoc;
        let cap = guard.default_tx_ring_capacity;
        guard.links.add_uds_stream_link(assoc, stream, cost, cap);
    }

    /// Attach any `AsyncRead + AsyncWrite` byte-stream link to the default association with `cost`.
    pub fn add_stream_link<S>(&self, stream: S, cost: u16)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let mut guard = self.core.lock().unwrap();
        let assoc = guard.default_assoc;
        let cap = guard.default_tx_ring_capacity;
        guard.links.add_stream_link(assoc, stream, cost, cap);
    }

    /// Attach any `AsyncRead + AsyncWrite` byte-stream link to an explicit `assoc`.
    pub fn add_stream_link_on<S>(
        &self,
        assoc: AssociationId,
        stream: S,
        cost: u16,
        tx_ring_capacity: usize,
    ) where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let mut guard = self.core.lock().unwrap();
        guard
            .links
            .add_stream_link(assoc, stream, cost, tx_ring_capacity);
    }

    /// Attach a `UnixDatagram` link to the default association with `cost`.
    pub fn add_datagram_link(&self, dgram: UnixDatagram, cost: u16) {
        let mut guard = self.core.lock().unwrap();
        let assoc = guard.default_assoc;
        let cap = guard.default_tx_ring_capacity;
        guard.links.add_datagram_link(assoc, dgram, cost, cap);
    }

    /// Attach a packet-oriented channel link (such as PPP serial port `245`) to the default
    /// association with `mtu` and `cost`.
    pub fn add_packet_link(
        &self,
        tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        mtu: usize,
        cost: u16,
    ) {
        let mut guard = self.core.lock().unwrap();
        let assoc = guard.default_assoc;
        let cap = guard.default_tx_ring_capacity;
        guard.links.add_packet_link(assoc, tx, rx, mtu, cost, cap);
    }

    /// Attach a packet-oriented channel link to an explicit `assoc`.
    pub fn add_packet_link_on(
        &self,
        assoc: AssociationId,
        tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        mtu: usize,
        cost: u16,
        tx_ring_capacity: usize,
    ) {
        let mut guard = self.core.lock().unwrap();
        guard
            .links
            .add_packet_link(assoc, tx, rx, mtu, cost, tx_ring_capacity);
    }

    /// Open a new bidirectional [`MuxStream`] on the default association (awaits if `MAX_STREAMS`
    /// concurrency limit is momentarily full).
    pub async fn open_bidi(&self) -> io::Result<MuxStream> {
        let assoc = self.core.lock().unwrap().default_assoc;
        self.open_stream_on(assoc, true, StreamPriority::NORMAL)
            .await
    }

    /// Open a new unidirectional [`MuxStream`] on the default association.
    pub async fn open_uni(&self) -> io::Result<MuxStream> {
        let assoc = self.core.lock().unwrap().default_assoc;
        self.open_stream_on(assoc, false, StreamPriority::NORMAL)
            .await
    }

    /// Open a new [`MuxStream`] on `assoc` with explicit direction and [`StreamPriority`].
    pub async fn open_stream_on(
        &self,
        assoc: AssociationId,
        bidi: bool,
        priority: StreamPriority,
    ) -> io::Result<MuxStream> {
        poll_fn(|cx| {
            let mut guard = self.core.lock().unwrap();
            if guard.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mux session is closed",
                )));
            }
            match guard.mux.open_stream_with_priority(assoc, bidi, priority) {
                Ok(sid) => {
                    let mut ep = StreamEndpointState::new();
                    if !bidi {
                        // Outbound unidirectional stream has no readable half.
                        ep.fin_queued = true;
                    }
                    guard.streams.insert((assoc, sid), ep);
                    drop(guard);
                    Poll::Ready(Ok(MuxStream::from_parts(
                        assoc,
                        sid,
                        self.core.clone(),
                        self.pool.clone(),
                        self.rx_reserve_slots,
                        self.lifecycle.clone(),
                    )))
                }
                Err(MuxError::StreamLimitReached) => {
                    guard.open_wakers.push(cx.waker().clone());
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    alloc::format!("failed to open stream: {e:?}"),
                ))),
            }
        })
        .await
    }

    /// Access the underlying packet pool for zero-copy packet preparation.
    #[inline]
    pub const fn pool(&self) -> &XipLazyPool {
        &self.pool
    }

    /// Allocate a uniquely-owned `XipLazyPacket` with headroom preserved (`range = headroom..headroom`),
    /// leaving RX reserve slots free.
    #[inline]
    pub fn alloc_packet(&self) -> Result<XipLazyPacket, PoolError> {
        self.pool.alloc_reserving(self.rx_reserve_slots)
    }

    /// Total number of small TX packets (`<= mtu / 3`) coalesced into pending packets across all links.
    pub fn coalesced_tx_packets(&self) -> u64 {
        self.core.lock().unwrap().links.coalesced_tx_packets()
    }
}

/// Owned read half of a [`MuxStream`], supporting **both** [`tokio::io::AsyncRead`] and zero-copy
/// [`Self::recv_chunk`] packet ownership transfer.
pub struct MuxReadHalf {
    assoc: AssociationId,
    stream_id: StreamId,
    core: Arc<Mutex<MuxCore>>,
    lifecycle: Arc<HandleLifecycle>,
    current_chunk: Option<(OwnedRxChunk, usize)>,
    pending_credit: usize,
}

impl Drop for MuxReadHalf {
    fn drop(&mut self) {
        // Release any active chunk (and its flow-control credit / pool slot) first.
        self.current_chunk.take();
        {
            if let Ok(mut guard) = self.core.lock() {
                let mut unread_credit = self.pending_credit;
                self.pending_credit = 0;
                let mut send_stop = false;
                let is_closed = guard.closed;
                if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                    ep.read_dropped = true;
                    ep.read_waker = None;
                    for item in ep.rx_queue.drain(..) {
                        unread_credit += item.credit_bytes;
                    }
                    if !ep.fin_queued && !ep.locally_reset && ep.rx_error.is_none() {
                        ep.fin_queued = true;
                        send_stop = !is_closed;
                    }
                }
                let mut wakers = Vec::new();
                if send_stop {
                    let MuxCore { mux, links, .. } = &mut *guard;
                    mux.stop_sending(self.assoc, self.stream_id, 0, links);
                } else if unread_credit > 0 {
                    wakers = guard.on_credit_released(self.assoc, self.stream_id, unread_credit);
                }
                guard.maybe_gc_stream(self.assoc, self.stream_id);
                drop(guard);
                for w in wakers {
                    w.wake();
                }
            }
        }
        self.lifecycle.dec();
    }
}

impl MuxReadHalf {
    /// Association ID of this stream.
    #[inline]
    pub const fn association_id(&self) -> AssociationId {
        self.assoc
    }

    /// QUIC `StreamId` of this stream.
    #[inline]
    pub const fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Receive the next chunk with zero-copy `XipLazyPacket` ownership transfer (`Ok(None)` at EOF).
    ///
    /// If an earlier `AsyncRead` call partially consumed the current chunk, returns the remaining
    /// unconsumed suffix of that chunk with its `PoolPacket` range trimmed in-place.
    ///
    /// Credit from the previous chunk is coalesced and released inside the next `recv_chunk()`
    /// lock acquisition when the caller drops or consumes the chunk before calling `recv_chunk()`
    /// again, avoiding a separate mutex lock per chunk on the hot path while still supporting
    /// immediate credit release if the chunk is held across hops and dropped asynchronously.
    pub async fn recv_chunk(&mut self) -> io::Result<Option<OwnedRxChunk>> {
        if let Some((mut chunk, offset)) = self.current_chunk.take() {
            if offset < chunk.len() {
                chunk.trim_prefix(offset);
                return Ok(Some(chunk));
            }
            drop(chunk);
        }

        poll_fn(|cx| {
            let mut guard = self.core.lock().unwrap();
            let mut wakers = Vec::new();
            if self.pending_credit > 0 {
                let cred = self.pending_credit;
                self.pending_credit = 0;
                wakers = guard.on_credit_released(self.assoc, self.stream_id, cred);
            }
            let closed = guard.closed;
            let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) else {
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Ok(None));
            };
            if let Some(reason) = ep.rx_error {
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Err(close_reason_to_io_error(reason)));
            }
            if let Some(item) = ep.rx_queue.pop_front() {
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Ok(Some(OwnedRxChunk::new(
                    item,
                    self.assoc,
                    self.stream_id,
                    self.core.clone(),
                ))));
            }
            if ep.fin_queued {
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Ok(None));
            }
            if closed {
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mux session closed before stream FIN",
                )));
            }
            ep.read_waker = Some(cx.waker().clone());
            drop(guard);
            for w in wakers {
                w.wake();
            }
            Poll::Pending
        })
        .await
    }

    /// Receive the next chunk and defer its credit release until the subsequent `recv_chunk*` call
    /// (or stream drop), avoiding a second mutex lock + `Arc::clone` on `Drop` when consuming
    /// chunks sequentially in a single task.
    pub async fn recv_chunk_coalesced(&mut self) -> io::Result<Option<OwnedRxChunk>> {
        if let Some((mut chunk, offset)) = self.current_chunk.take() {
            if offset < chunk.len() {
                chunk.trim_prefix(offset);
                return Ok(Some(chunk));
            }
            drop(chunk);
        }

        poll_fn(|cx| {
            let mut guard = self.core.lock().unwrap();
            let mut wakers = Vec::new();
            if self.pending_credit > 0 {
                let cred = self.pending_credit;
                self.pending_credit = 0;
                wakers = guard.on_credit_released(self.assoc, self.stream_id, cred);
            }
            let closed = guard.closed;
            let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) else {
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Ok(None));
            };
            if let Some(reason) = ep.rx_error {
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Err(close_reason_to_io_error(reason)));
            }
            if let Some(item) = ep.rx_queue.pop_front() {
                self.pending_credit += item.credit_bytes;
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Ok(Some(OwnedRxChunk {
                    payload: Some(item.payload),
                    fin: item.fin,
                    assoc: self.assoc,
                    stream_id: self.stream_id,
                    unreleased_credit: 0,
                    core: None,
                })));
            }
            if ep.fin_queued {
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Ok(None));
            }
            if closed {
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mux session closed before stream FIN",
                )));
            }
            ep.read_waker = Some(cx.waker().clone());
            drop(guard);
            for w in wakers {
                w.wake();
            }
            Poll::Pending
        })
        .await
    }

    /// Drain all currently queued chunks in a single mutex lock acquisition, invoking
    /// `on_chunk(bytes, is_fin)` on each zero-copy slice in place, releasing all consumed
    /// flow-control credit and pool slots immediately (`Ok(0)` at EOF).
    pub async fn recv_chunks_drained<F>(&mut self, mut on_chunk: F) -> io::Result<usize>
    where
        F: FnMut(&[u8], bool),
    {
        if let Some((chunk, offset)) = self.current_chunk.take() {
            let slice = chunk.bytes();
            if offset < slice.len() {
                let avail = &slice[offset..];
                let len = avail.len();
                on_chunk(avail, chunk.is_fin());
                drop(chunk);
                return Ok(len);
            }
            drop(chunk);
        }

        poll_fn(|cx| {
            let mut guard = self.core.lock().unwrap();
            let mut released_credit = self.pending_credit;
            self.pending_credit = 0;
            let closed = guard.closed;
            let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) else {
                let wakers = if released_credit > 0 {
                    guard.on_credit_released(self.assoc, self.stream_id, released_credit)
                } else {
                    Vec::new()
                };
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Ok(0));
            };
            if let Some(reason) = ep.rx_error {
                let wakers = if released_credit > 0 {
                    guard.on_credit_released(self.assoc, self.stream_id, released_credit)
                } else {
                    Vec::new()
                };
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Err(close_reason_to_io_error(reason)));
            }
            if !ep.rx_queue.is_empty() {
                let mut total_bytes = 0usize;
                while let Some(item) = ep.rx_queue.pop_front() {
                    let slice = item.payload.bytes();
                    total_bytes += slice.len();
                    on_chunk(slice, item.fin);
                    released_credit += item.credit_bytes;
                }
                let wakers = if released_credit > 0 {
                    guard.on_credit_released(self.assoc, self.stream_id, released_credit)
                } else {
                    Vec::new()
                };
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Ok(total_bytes));
            }
            if ep.fin_queued {
                let wakers = if released_credit > 0 {
                    guard.on_credit_released(self.assoc, self.stream_id, released_credit)
                } else {
                    Vec::new()
                };
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Ok(0));
            }
            if closed {
                let wakers = if released_credit > 0 {
                    guard.on_credit_released(self.assoc, self.stream_id, released_credit)
                } else {
                    Vec::new()
                };
                drop(guard);
                for w in wakers {
                    w.wake();
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mux session closed before stream FIN",
                )));
            }
            ep.read_waker = Some(cx.waker().clone());
            let wakers = if released_credit > 0 {
                guard.on_credit_released(self.assoc, self.stream_id, released_credit)
            } else {
                Vec::new()
            };
            drop(guard);
            for w in wakers {
                w.wake();
            }
            Poll::Pending
        })
        .await
    }
}

impl AsyncRead for MuxReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if let Some((chunk, offset)) = &mut self.current_chunk {
            let slice = chunk.bytes();
            if *offset < slice.len() {
                let avail = &slice[*offset..];
                let to_copy = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..to_copy]);
                *offset += to_copy;
                if *offset >= slice.len() {
                    self.current_chunk.take();
                }
                return Poll::Ready(Ok(()));
            }
            self.current_chunk.take();
        }

        let assoc = self.assoc;
        let sid = self.stream_id;
        let mut released_credit = self.pending_credit;
        self.pending_credit = 0;
        let mut guard = self.core.lock().unwrap();
        let closed = guard.closed;
        let Some(ep) = guard.streams.get_mut(&(assoc, sid)) else {
            let wakers = if released_credit > 0 {
                guard.on_credit_released(assoc, sid, released_credit)
            } else {
                Vec::new()
            };
            drop(guard);
            for w in wakers {
                w.wake();
            }
            return Poll::Ready(Ok(()));
        };
        if let Some(reason) = ep.rx_error {
            let wakers = if released_credit > 0 {
                guard.on_credit_released(assoc, sid, released_credit)
            } else {
                Vec::new()
            };
            drop(guard);
            for w in wakers {
                w.wake();
            }
            return Poll::Ready(Err(close_reason_to_io_error(reason)));
        }

        let mut copied_any = false;
        let mut partial_chunk: Option<(OwnedRxChunk, usize)> = None;
        while buf.remaining() > 0 {
            let Some(item) = ep.rx_queue.pop_front() else {
                break;
            };
            let slice = item.payload.bytes();
            if slice.len() <= buf.remaining() {
                buf.put_slice(slice);
                released_credit += item.credit_bytes;
                copied_any = true;
                // `item.payload` drops here, returning the pool slot immediately!
            } else {
                let to_copy = buf.remaining();
                buf.put_slice(&slice[..to_copy]);
                copied_any = true;
                partial_chunk = Some((
                    OwnedRxChunk::new(item, assoc, sid, self.core.clone()),
                    to_copy,
                ));
                break;
            }
        }

        if copied_any {
            let wakers = if released_credit > 0 {
                guard.on_credit_released(assoc, sid, released_credit)
            } else {
                Vec::new()
            };
            drop(guard);
            self.current_chunk = partial_chunk;
            for w in wakers {
                w.wake();
            }
            return Poll::Ready(Ok(()));
        }

        if ep.fin_queued {
            let wakers = if released_credit > 0 {
                guard.on_credit_released(assoc, sid, released_credit)
            } else {
                Vec::new()
            };
            drop(guard);
            for w in wakers {
                w.wake();
            }
            return Poll::Ready(Ok(()));
        }
        if closed {
            let wakers = if released_credit > 0 {
                guard.on_credit_released(assoc, sid, released_credit)
            } else {
                Vec::new()
            };
            drop(guard);
            for w in wakers {
                w.wake();
            }
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "mux session closed before stream FIN",
            )));
        }
        ep.read_waker = Some(cx.waker().clone());
        let wakers = if released_credit > 0 {
            guard.on_credit_released(assoc, sid, released_credit)
        } else {
            Vec::new()
        };
        drop(guard);
        for w in wakers {
            w.wake();
        }
        Poll::Pending
    }
}

/// Owned write half of a [`MuxStream`], supporting **both** [`tokio::io::AsyncWrite`] and zero-copy
/// [`Self::send_packet`] `XipLazyPacket` ownership passing.
pub struct MuxWriteHalf {
    assoc: AssociationId,
    stream_id: StreamId,
    core: Arc<Mutex<MuxCore>>,
    pool: XipLazyPool,
    rx_reserve_slots: usize,
    lifecycle: Arc<HandleLifecycle>,
}

impl Drop for MuxWriteHalf {
    fn drop(&mut self) {
        {
            if let Ok(mut guard) = self.core.lock() {
                let mut need_fin = false;
                if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                    ep.write_dropped = true;
                    ep.write_waker = None;
                    if !ep.local_fin_sent
                        && !ep.locally_reset
                        && ep.tx_error.is_none()
                        && !guard.closed
                    {
                        need_fin = true;
                    }
                }
                if need_fin {
                    let MuxCore { mux, links, .. } = &mut *guard;
                    match mux.write_stream(
                        self.assoc,
                        self.stream_id,
                        TxStreamData::Bytes(&[]),
                        true,
                        links,
                    ) {
                        Ok(_)
                        | Err(MuxSendError::Error {
                            error:
                                MuxError::StreamFinished
                                | MuxError::UnknownStream
                                | MuxError::StreamReset
                                | MuxError::InvalidStreamState,
                            ..
                        }) => {
                            if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id))
                            {
                                ep.local_fin_sent = true;
                            }
                        }
                        _ => {
                            guard.pending_fins.push_back((self.assoc, self.stream_id));
                        }
                    }
                }
                guard.maybe_gc_stream(self.assoc, self.stream_id);
            }
        }
        self.lifecycle.dec();
    }
}

impl MuxWriteHalf {
    /// Association ID of this stream.
    #[inline]
    pub const fn association_id(&self) -> AssociationId {
        self.assoc
    }

    /// QUIC `StreamId` of this stream.
    #[inline]
    pub const fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Access the underlying packet pool for zero-copy packet allocation.
    #[inline]
    pub const fn pool(&self) -> &XipLazyPool {
        &self.pool
    }

    /// Allocate a uniquely-owned `XipLazyPacket` with headroom preserved (`range = headroom..headroom`)
    /// so the caller can populate payload bytes directly in-place and pass ownership to [`Self::send_packet`].
    #[inline]
    pub fn alloc_packet(&self) -> Result<XipLazyPacket, PoolError> {
        self.pool.alloc_reserving(self.rx_reserve_slots)
    }

    /// Asynchronously wait until **both** stream/association flow-control + link space **and** a
    /// packet pool slot are available, then return `(XipLazyPacket, max_payload_bytes)`.
    ///
    /// Unlike calling [`Self::alloc_packet`] in a loop before [`Self::send_packet`], this method
    /// uses event-driven waker notification (never busy-yielding) and never pins a pool slot while
    /// the stream is blocked on flow control.
    pub async fn alloc_packet_async(&mut self) -> io::Result<(XipLazyPacket, usize)> {
        poll_fn(|cx| {
            let mut guard = self.core.lock().unwrap();
            if guard.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mux session is closed",
                )));
            }
            if let Some(ep) = guard.streams.get(&(self.assoc, self.stream_id)) {
                if let Some(reason) = ep.tx_error {
                    return Poll::Ready(Err(close_reason_to_io_error(reason)));
                }
                if ep.local_fin_sent {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "stream already finished",
                    )));
                }
            } else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stream is closed",
                )));
            }

            if self.pool.available() <= self.rx_reserve_slots {
                if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                    ep.write_waker = Some(cx.waker().clone());
                }
                return Poll::Pending;
            }

            let cap = match guard
                .mux
                .stream_send_capacity(self.assoc, self.stream_id, &guard.links)
            {
                Ok(c) => c,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        alloc::format!("stream capacity error: {e:?}"),
                    )));
                }
            };

            if !cap.can_send_now || cap.max_chunk_bytes == 0 {
                if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                    ep.write_waker = Some(cx.waker().clone());
                }
                return Poll::Pending;
            }

            match self.pool.alloc_reserving(self.rx_reserve_slots) {
                Ok(pkt) => Poll::Ready(Ok((pkt, cap.max_chunk_bytes))),
                Err(PoolError::Exhausted) => {
                    if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                        ep.write_waker = Some(cx.waker().clone());
                    }
                    Poll::Pending
                }
                Err(other) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    alloc::format!("pool alloc failed: {other:?}"),
                ))),
            }
        })
        .await
    }

    /// Dynamically adjust this stream's priority.
    pub fn set_priority(&self, priority: StreamPriority) {
        if let Ok(mut guard) = self.core.lock() {
            let _ = guard
                .mux
                .set_stream_priority(self.assoc, self.stream_id, priority);
        }
    }

    /// Immediately abort this stream (`RESET_STREAM` + `STOP_SENDING`) with `error_code`.
    pub fn reset(&mut self, error_code: u64) {
        if let Ok(mut guard) = self.core.lock() {
            let mut wakers = Vec::new();
            if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                ep.locally_reset = true;
                ep.rx_queue.clear();
                if let Some(w) = ep.read_waker.take() {
                    wakers.push(w);
                }
                if let Some(w) = ep.write_waker.take() {
                    wakers.push(w);
                }
            }
            let MuxCore { mux, links, .. } = &mut *guard;
            mux.reset_stream(self.assoc, self.stream_id, error_code, links);
            guard.maybe_gc_stream(self.assoc, self.stream_id);
            drop(guard);
            for w in wakers {
                w.wake();
            }
        }
    }

    /// Send a caller-owned `XipLazyPacket` with zero payload copies!
    ///
    /// - `QuicMux` prepends the `STREAM` frame header directly into `packet`'s headroom (`< 144`),
    ///   and the selected link prepends its link header in front of that.
    /// - If blocked by flow control (`MAX_STREAM_DATA` / `MAX_DATA` / device capacity) or link
    ///   `Busy`, `packet` is retained across `.await` with its original payload range intact and
    ///   transmitted zero-copy as soon as window/link space opens up.
    pub async fn send_packet(&mut self, packet: XipLazyPacket, fin: bool) -> io::Result<usize> {
        let mut pkt_opt = Some(packet);
        poll_fn(|cx| {
            let pkt = pkt_opt.take().expect("polled after completion");
            let mut guard = self.core.lock().unwrap();
            if guard.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mux session is closed",
                )));
            }
            if let Some(ep) = guard.streams.get(&(self.assoc, self.stream_id)) {
                if let Some(reason) = ep.tx_error {
                    return Poll::Ready(Err(close_reason_to_io_error(reason)));
                }
                if ep.local_fin_sent {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "stream already finished",
                    )));
                }
            } else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stream is closed",
                )));
            }

            let MuxCore { mux, links, .. } = &mut *guard;
            match mux.write_stream(
                self.assoc,
                self.stream_id,
                TxStreamData::Packet(pkt),
                fin,
                links,
            ) {
                Ok(n) => {
                    if fin {
                        if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                            ep.local_fin_sent = true;
                        }
                    }
                    Poll::Ready(Ok(n))
                }
                Err(MuxSendError::Busy(Some(returned)))
                | Err(MuxSendError::FlowControl(Some(returned))) => {
                    pkt_opt = Some(returned);
                    if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                        ep.write_waker = Some(cx.waker().clone());
                    }
                    Poll::Pending
                }
                Err(MuxSendError::PacketTooLarge { max_payload, .. }) => {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        alloc::format!("packet payload exceeds max link payload ({max_payload})"),
                    )))
                }
                Err(other) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    alloc::format!("send_packet failed: {other:?}"),
                ))),
            }
        })
        .await
    }

    /// Zero-copy in-place packet preparation and transmission in a **single** lock acquisition.
    ///
    /// Waits on `ep.write_waker` until stream/association flow-control + link space and a packet
    /// pool slot are available, allocates an `XipLazyPacket`, invokes `populate(&mut [u8]) -> usize`
    /// on the writable payload slice starting at `headroom`, sets the packet range, and calls
    /// `write_stream(TxStreamData::Packet(pkt))` inside the same `MuxCore` lock scope.
    pub async fn send_in_place<F>(&mut self, fin: bool, mut populate: F) -> io::Result<usize>
    where
        F: FnMut(&mut [u8]) -> usize,
    {
        poll_fn(|cx| {
            let mut guard = self.core.lock().unwrap();
            if guard.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mux session is closed",
                )));
            }
            if let Some(ep) = guard.streams.get(&(self.assoc, self.stream_id)) {
                if let Some(reason) = ep.tx_error {
                    return Poll::Ready(Err(close_reason_to_io_error(reason)));
                }
                if ep.local_fin_sent {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "stream already finished",
                    )));
                }
            } else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stream is closed",
                )));
            }

            if self.pool.available() <= self.rx_reserve_slots {
                if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                    ep.write_waker = Some(cx.waker().clone());
                }
                return Poll::Pending;
            }

            let cap = match guard
                .mux
                .stream_send_capacity(self.assoc, self.stream_id, &guard.links)
            {
                Ok(c) => c,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        alloc::format!("stream capacity error: {e:?}"),
                    )));
                }
            };

            if !cap.can_send_now || cap.max_chunk_bytes == 0 {
                if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                    ep.write_waker = Some(cx.waker().clone());
                }
                return Poll::Pending;
            }

            let mut pkt = match self.pool.alloc_reserving(self.rx_reserve_slots) {
                Ok(p) => p,
                Err(PoolError::Exhausted) => {
                    if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                        ep.write_waker = Some(cx.waker().clone());
                    }
                    return Poll::Pending;
                }
                Err(other) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        alloc::format!("pool alloc failed: {other:?}"),
                    )));
                }
            };

            let h = pkt.range().start;
            let written = {
                let slot = pkt.slot_slice_mut().map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "fresh pool packet not unique")
                })?;
                let avail_slice = &mut slot[h..h + cap.max_chunk_bytes];
                populate(avail_slice)
            };
            if written > cap.max_chunk_bytes {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "populate returned more bytes than available slice length",
                )));
            }
            pkt.set_range(h..h + written)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid packet range"))?;

            let MuxCore { mux, links, .. } = &mut *guard;
            match mux.write_stream(
                self.assoc,
                self.stream_id,
                TxStreamData::Packet(pkt),
                fin,
                links,
            ) {
                Ok(n) => {
                    if fin {
                        if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                            ep.local_fin_sent = true;
                        }
                    }
                    Poll::Ready(Ok(n))
                }
                Err(MuxSendError::Busy(_))
                | Err(MuxSendError::FlowControl(_))
                | Err(MuxSendError::Error {
                    error: MuxError::Pool(PoolError::Exhausted),
                    ..
                }) => {
                    if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                        ep.write_waker = Some(cx.waker().clone());
                    }
                    Poll::Pending
                }
                Err(other) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    alloc::format!("send_in_place failed: {other:?}"),
                ))),
            }
        })
        .await
    }

    /// Gracefully finish the outbound half of this stream (sends `FIN` and flushes to the link).
    pub async fn finish(&mut self) -> io::Result<()> {
        tokio::io::AsyncWriteExt::shutdown(self).await
    }
}

impl AsyncWrite for MuxWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut guard = self.core.lock().unwrap();
        if guard.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mux session is closed",
            )));
        }
        if let Some(ep) = guard.streams.get(&(self.assoc, self.stream_id)) {
            if let Some(reason) = ep.tx_error {
                return Poll::Ready(Err(close_reason_to_io_error(reason)));
            }
            if ep.local_fin_sent {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stream already shut down",
                )));
            }
        } else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream is closed",
            )));
        }

        if self.pool.available() <= self.rx_reserve_slots {
            if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                ep.write_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }

        let cap = match guard
            .mux
            .stream_send_capacity(self.assoc, self.stream_id, &guard.links)
        {
            Ok(c) => c,
            Err(e) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    alloc::format!("stream capacity error: {e:?}"),
                )));
            }
        };

        if !cap.can_send_now || cap.max_chunk_bytes == 0 {
            if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                ep.write_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }

        let to_send = buf.len().min(cap.max_chunk_bytes);
        let MuxCore { mux, links, .. } = &mut *guard;
        match mux.write_stream(
            self.assoc,
            self.stream_id,
            TxStreamData::Bytes(&buf[..to_send]),
            false,
            links,
        ) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(MuxSendError::Busy(_))
            | Err(MuxSendError::FlowControl(_))
            | Err(MuxSendError::Error {
                error: MuxError::Pool(PoolError::Exhausted),
                ..
            }) => {
                if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                    ep.write_waker = Some(cx.waker().clone());
                }
                Poll::Pending
            }
            Err(other) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                alloc::format!("write_stream failed: {other:?}"),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.core.lock().unwrap();
        if let Some(ep) = guard.streams.get(&(self.assoc, self.stream_id)) {
            if let Some(reason) = ep.tx_error {
                return Poll::Ready(Err(close_reason_to_io_error(reason)));
            }
        }
        if guard.closed || guard.links.is_assoc_flushed(self.assoc) {
            return Poll::Ready(Ok(()));
        }
        if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
            ep.write_waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.core.lock().unwrap();
        let already_sent = match guard.streams.get(&(self.assoc, self.stream_id)) {
            Some(ep) => {
                if let Some(reason) = ep.tx_error {
                    return Poll::Ready(Err(close_reason_to_io_error(reason)));
                }
                ep.local_fin_sent
            }
            None => return Poll::Ready(Ok(())),
        };

        if !already_sent && !guard.closed {
            let MuxCore { mux, links, .. } = &mut *guard;
            match mux.write_stream(
                self.assoc,
                self.stream_id,
                TxStreamData::Bytes(&[]),
                true,
                links,
            ) {
                Ok(_)
                | Err(MuxSendError::Error {
                    error:
                        MuxError::StreamFinished
                        | MuxError::UnknownStream
                        | MuxError::StreamReset
                        | MuxError::InvalidStreamState,
                    ..
                }) => {
                    if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                        ep.local_fin_sent = true;
                    }
                }
                Err(MuxSendError::Busy(_))
                | Err(MuxSendError::FlowControl(_))
                | Err(MuxSendError::Error {
                    error: MuxError::Pool(PoolError::Exhausted),
                    ..
                }) => {
                    if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
                        ep.write_waker = Some(cx.waker().clone());
                    }
                    return Poll::Pending;
                }
                Err(other) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        alloc::format!("shutdown failed: {other:?}"),
                    )));
                }
            }
        }

        if guard.closed || guard.links.is_assoc_flushed(self.assoc) {
            return Poll::Ready(Ok(()));
        }
        if let Some(ep) = guard.streams.get_mut(&(self.assoc, self.stream_id)) {
            ep.write_waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }
}

/// Duplex multiplexed stream supporting **both**:
/// - Traditional `tokio::io::AsyncRead + tokio::io::AsyncWrite` (drop-in `TcpStream` substitute), AND
/// - Zero-copy packet pool ownership passing (`alloc_packet`, `send_packet`, `recv_chunk`).
pub struct MuxStream {
    read: MuxReadHalf,
    write: MuxWriteHalf,
}

impl MuxStream {
    fn from_parts(
        assoc: AssociationId,
        stream_id: StreamId,
        core: Arc<Mutex<MuxCore>>,
        pool: XipLazyPool,
        rx_reserve_slots: usize,
        lifecycle: Arc<HandleLifecycle>,
    ) -> Self {
        // Increment once for `MuxReadHalf` and once for `MuxWriteHalf`.
        lifecycle.inc();
        lifecycle.inc();
        Self {
            read: MuxReadHalf {
                assoc,
                stream_id,
                core: core.clone(),
                lifecycle: lifecycle.clone(),
                current_chunk: None,
                pending_credit: 0,
            },
            write: MuxWriteHalf {
                assoc,
                stream_id,
                core,
                pool,
                rx_reserve_slots,
                lifecycle,
            },
        }
    }

    /// Association ID of this stream.
    #[inline]
    pub const fn association_id(&self) -> AssociationId {
        self.read.association_id()
    }

    /// QUIC `StreamId` of this stream.
    #[inline]
    pub const fn stream_id(&self) -> StreamId {
        self.read.stream_id()
    }

    /// Split into owned `Send + 'static` read and write halves (like `TcpStream::into_split`).
    #[inline]
    pub fn into_split(self) -> (MuxReadHalf, MuxWriteHalf) {
        (self.read, self.write)
    }

    /// Borrow mutable references to the read and write halves.
    #[inline]
    pub fn split(&mut self) -> (&mut MuxReadHalf, &mut MuxWriteHalf) {
        (&mut self.read, &mut self.write)
    }

    /// Access the underlying packet pool for zero-copy packet allocation.
    #[inline]
    pub const fn pool(&self) -> &XipLazyPool {
        self.write.pool()
    }

    /// Allocate a uniquely-owned `XipLazyPacket` with headroom preserved (`range = headroom..headroom`).
    #[inline]
    pub fn alloc_packet(&self) -> Result<XipLazyPacket, PoolError> {
        self.write.alloc_packet()
    }

    /// Asynchronously wait until both flow-control + link space and a packet pool slot are
    /// available, then return `(XipLazyPacket, max_payload_bytes)`.
    #[inline]
    pub async fn alloc_packet_async(&mut self) -> io::Result<(XipLazyPacket, usize)> {
        self.write.alloc_packet_async().await
    }

    /// Send a caller-owned `XipLazyPacket` with zero payload copies.
    #[inline]
    pub async fn send_packet(&mut self, packet: XipLazyPacket, fin: bool) -> io::Result<usize> {
        self.write.send_packet(packet, fin).await
    }

    /// Zero-copy in-place packet preparation and transmission in a single lock acquisition.
    #[inline]
    pub async fn send_in_place<F>(&mut self, fin: bool, populate: F) -> io::Result<usize>
    where
        F: FnMut(&mut [u8]) -> usize,
    {
        self.write.send_in_place(fin, populate).await
    }

    /// Receive the next chunk with zero-copy `XipLazyPacket` ownership transfer (`Ok(None)` at EOF).
    #[inline]
    pub async fn recv_chunk(&mut self) -> io::Result<Option<OwnedRxChunk>> {
        self.read.recv_chunk().await
    }

    /// Receive the next chunk and coalesce its credit release into the subsequent `recv_chunk*`
    /// call (or stream drop) to avoid a second mutex lock + `Arc::clone` on `Drop`.
    #[inline]
    pub async fn recv_chunk_coalesced(&mut self) -> io::Result<Option<OwnedRxChunk>> {
        self.read.recv_chunk_coalesced().await
    }

    /// Drain all currently queued chunks in a single mutex lock acquisition, invoking
    /// `on_chunk(bytes, is_fin)` on each zero-copy slice in place (`Ok(0)` at EOF).
    #[inline]
    pub async fn recv_chunks_drained<F>(&mut self, on_chunk: F) -> io::Result<usize>
    where
        F: FnMut(&[u8], bool),
    {
        self.read.recv_chunks_drained(on_chunk).await
    }

    /// Dynamically adjust this stream's priority.
    #[inline]
    pub fn set_priority(&self, priority: StreamPriority) {
        self.write.set_priority(priority);
    }

    /// Immediately abort this stream (`RESET_STREAM` + `STOP_SENDING`) with `error_code`.
    #[inline]
    pub fn reset(&mut self, error_code: u64) {
        self.write.reset(error_code);
    }

    /// Gracefully finish the outbound half of this stream.
    #[inline]
    pub async fn finish(&mut self) -> io::Result<()> {
        self.write.finish().await
    }
}

impl AsyncRead for MuxStream {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl AsyncWrite for MuxStream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}
