//! Core `QuicMux` stream multiplexer, 3-tier flow control, dynamic pressure eviction, and zero-copy packet dispatch.

#[cfg(feature = "btree")]
use alloc::collections::BTreeMap as MuxMap;
use alloc::vec::Vec;

#[cfg(not(feature = "btree"))]
struct MuxMap<K, V>(Vec<(K, V)>);

#[cfg(not(feature = "btree"))]
impl<K, V> Default for MuxMap<K, V> {
    #[inline]
    fn default() -> Self {
        Self(Vec::new())
    }
}

#[cfg(not(feature = "btree"))]
impl<K: Ord, V> MuxMap<K, V> {
    #[inline]
    const fn new() -> Self {
        Self(Vec::new())
    }

    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn contains_key(&self, key: &K) -> bool {
        self.0.iter().any(|(k, _)| k == key)
    }

    #[inline]
    fn get(&self, key: &K) -> Option<&V> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    #[inline]
    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.0.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn insert(&mut self, key: K, value: V) -> Option<V> {
        let mut idx = 0;
        while idx < self.0.len() {
            if self.0[idx].0 == key {
                return Some(core::mem::replace(&mut self.0[idx].1, value));
            }
            if self.0[idx].0 > key {
                break;
            }
            idx += 1;
        }
        self.0.insert(idx, (key, value));
        None
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        let idx = self.0.iter().position(|(k, _)| k == key)?;
        Some(self.0.remove(idx).1)
    }

    #[inline]
    fn values(&self) -> core::iter::Map<core::slice::Iter<'_, (K, V)>, fn(&(K, V)) -> &V> {
        self.0.iter().map(|(_, v)| v)
    }
}

#[cfg(not(feature = "btree"))]
impl<K, V> IntoIterator for MuxMap<K, V> {
    type Item = (K, V);
    type IntoIter = alloc::vec::IntoIter<(K, V)>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(not(feature = "btree"))]
impl<'a, K, V> IntoIterator for &'a MuxMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter =
        core::iter::Map<core::slice::Iter<'a, (K, V)>, fn(&'a (K, V)) -> (&'a K, &'a V)>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter().map(|(k, v)| (k, v))
    }
}

#[cfg(not(feature = "btree"))]
impl<'a, K, V> IntoIterator for &'a mut MuxMap<K, V> {
    type Item = (&'a K, &'a mut V);
    type IntoIter =
        core::iter::Map<core::slice::IterMut<'a, (K, V)>, fn(&'a mut (K, V)) -> (&'a K, &'a mut V)>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut().map(|(k, v)| (&*k, v))
    }
}

use crate::flow::{
    AssociationBrokenReason, GAP_TIMEOUT_ERROR_CODE, MuxCallbacks, RESOURCE_PRESSURE_ERROR_CODE,
    RecvFlowControl, RxOutcome, SendFlowControl, StreamCloseReason, StreamPriority,
    StreamSendCapacity,
};
use crate::link::{AssociationEgress, AssociationId, LinkSendError, RxMeta, TxPacketMeta};
use crate::pool::{PacketPool, PoolError, PoolPacket};
use crate::streams::{QueuedPayload, ReassemblyError, RxStreamChunk, StreamState, TxStreamData};
use crate::wire::{
    Frame, StreamFrameRange, StreamId, WireError, decode_frame, encode_control_frame,
    encode_stream_header,
};

/// Dynamic per-association resource limits that can be increased or decreased at runtime based on load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssociationLimits {
    /// Maximum concurrent active streams on this association.
    pub max_concurrent_streams: usize,
    /// Maximum total out-of-order/paused RX `PoolPacket` chunks retained across all streams in this association.
    pub max_rx_queued_packets: usize,
    /// Maximum out-of-order/paused RX `PoolPacket` chunks retained by any single stream in this association.
    pub max_rx_queued_packets_per_stream: usize,
}

/// Configuration limits for [`QuicMux`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MuxLimits {
    /// Initial association-level `MAX_DATA` window (bytes).
    pub initial_max_data: u64,
    /// Initial per-stream `MAX_STREAM_DATA` window (bytes).
    pub initial_max_stream_data: u64,
    /// Initial peer-initiated bidirectional stream limit (`MAX_STREAMS_BIDI`).
    pub initial_max_streams_bidi: u64,
    /// Initial peer-initiated unidirectional stream limit (`MAX_STREAMS_UNI`).
    pub initial_max_streams_uni: u64,
    /// Initial maximum concurrent active streams per association.
    pub max_concurrent_streams: usize,
    /// Initial maximum out-of-order `PoolPacket` chunks retained per stream.
    pub max_queued_chunks_per_stream: usize,
    /// Initial maximum out-of-order `PoolPacket` chunks retained per association.
    pub max_association_rx_packets: usize,
    /// Initial device-wide maximum out-of-order `PoolPacket` chunks retained across all associations.
    pub max_device_rx_packets: usize,
    /// Timeout in microseconds before a missing middle frame on an out-of-order stream
    /// declares the stream (`GapTimeout` / RST) and association (`StreamGapTimeout`) broken.
    pub gap_timeout_us: u64,
}

impl Default for MuxLimits {
    fn default() -> Self {
        Self {
            initial_max_data: 64 * 1024,
            initial_max_stream_data: 16 * 1024,
            initial_max_streams_bidi: 16,
            initial_max_streams_uni: 16,
            max_concurrent_streams: 16,
            max_queued_chunks_per_stream: 8,
            max_association_rx_packets: 16,
            max_device_rx_packets: 32,
            gap_timeout_us: 3_000_000, // 3 seconds default
        }
    }
}

impl MuxLimits {
    /// Extract the default per-association dynamic limits from `self`.
    #[inline]
    pub const fn association_limits(&self) -> AssociationLimits {
        AssociationLimits {
            max_concurrent_streams: self.max_concurrent_streams,
            max_rx_queued_packets: self.max_association_rx_packets,
            max_rx_queued_packets_per_stream: self.max_queued_chunks_per_stream,
        }
    }
}

/// General errors returned by [`QuicMux`] operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MuxError {
    /// Association ID is not registered.
    UnknownAssociation,
    /// Association ID is already registered.
    DuplicateAssociation,
    /// Stream ID does not exist or is closed.
    UnknownStream,
    /// Peer `MAX_STREAMS` or local `max_concurrent_streams` limit reached.
    StreamLimitReached,
    /// Received frame violated `MAX_DATA` or `MAX_STREAM_DATA` flow control.
    FlowControlViolation,
    /// Out-of-order reassembly error.
    Reassembly(ReassemblyError),
    /// Wire codec error.
    Wire(WireError),
    /// Packet pool error.
    Pool(PoolError),
    /// Stream has already sent `FIN`.
    StreamFinished,
    /// Stream direction or state forbids this frame or operation (RFC 9000 §3).
    InvalidStreamState,
    /// Outbound stream was stopped by peer `STOP_SENDING` or locally reset.
    StreamReset,
}

/// Errors returned by [`QuicMux::write_stream`], preserving ownership of caller-supplied `PoolPacket`.
#[derive(Debug, PartialEq, Eq)]
pub enum MuxSendError<P> {
    /// Link/association layer refused the packet (`Busy`); caller's `PoolPacket` (if any) is returned
    /// with its original payload range restored.
    Busy(Option<P>),
    /// Blocked by device capacity, association `MAX_DATA`, or stream `MAX_STREAM_DATA`.
    FlowControl(Option<P>),
    /// Payload exceeds the association's current writable frame MTU.
    PacketTooLarge {
        /// Returned caller packet lease, if supplied.
        packet: Option<P>,
        /// Maximum payload bytes that fit in the current link frame.
        max_payload: usize,
    },
    /// Protocol, pool, or state error.
    Error {
        /// Returned caller packet lease, if supplied.
        packet: Option<P>,
        /// Underlying error.
        error: MuxError,
    },
}

struct AssociationState<P: PoolPacket> {
    is_client: bool,
    limits: AssociationLimits,
    recv_fc: RecvFlowControl,
    send_fc: SendFlowControl,
    next_local_bidi_index: u64,
    next_local_uni_index: u64,
    next_peer_bidi_index: u64,
    next_peer_uni_index: u64,
    peer_max_streams_bidi: u64,
    peer_max_streams_uni: u64,
    local_max_streams_bidi: u64,
    pending_max_streams_bidi: bool,
    local_max_streams_uni: u64,
    pending_max_streams_uni: bool,
    streams: MuxMap<StreamId, StreamState<P>>,
}

impl<P: PoolPacket> AssociationState<P> {
    fn new(is_client: bool, limits: &MuxLimits) -> Self {
        Self {
            is_client,
            limits: limits.association_limits(),
            recv_fc: RecvFlowControl::new(limits.initial_max_data),
            send_fc: SendFlowControl::new(limits.initial_max_data),
            next_local_bidi_index: 0,
            next_local_uni_index: 0,
            next_peer_bidi_index: 0,
            next_peer_uni_index: 0,
            peer_max_streams_bidi: limits.initial_max_streams_bidi,
            peer_max_streams_uni: limits.initial_max_streams_uni,
            local_max_streams_bidi: limits.initial_max_streams_bidi,
            pending_max_streams_bidi: false,
            local_max_streams_uni: limits.initial_max_streams_uni,
            pending_max_streams_uni: false,
            streams: MuxMap::new(),
        }
    }

    #[inline]
    fn is_peer_initiated(&self, stream_id: StreamId) -> bool {
        stream_id.is_client_initiated() != self.is_client
    }

    #[inline]
    fn has_local_send(&self, stream_id: StreamId) -> bool {
        stream_id.is_bidi() || !self.is_peer_initiated(stream_id)
    }

    #[inline]
    fn has_local_recv(&self, stream_id: StreamId) -> bool {
        stream_id.is_bidi() || self.is_peer_initiated(stream_id)
    }

    fn rx_queued_packets(&self) -> usize {
        self.streams.values().map(|s| s.rx.queued_chunks()).sum()
    }

    fn release_unconsumed_rx_credit(&mut self, st: &mut StreamState<P>, allow_slide: bool) {
        let unconsumed = st
            .recv_fc
            .highest_received()
            .saturating_sub(st.recv_fc.consumed());
        if unconsumed > 0 {
            st.recv_fc.on_consumed(unconsumed, false);
            self.recv_fc.on_consumed(unconsumed, allow_slide);
        }
    }

    fn retire_stream(&mut self, stream_id: StreamId, allow_slide: bool) -> Option<StreamState<P>> {
        let mut st = self.streams.remove(&stream_id)?;
        self.release_unconsumed_rx_credit(&mut st, allow_slide);
        st.rx.clear();
        self.on_stream_removed(stream_id);
        Some(st)
    }

    /// Ensure `stream_id` exists if it is a newly opened peer-initiated stream, enforcing:
    /// - Peer initiator parity vs `self.is_client`,
    /// - `local_max_streams_bidi` / `local_max_streams_uni` (`MAX_STREAMS`),
    /// - `max_concurrent_streams` across all implicitly opened stream indices `next_peer_*..=idx`,
    /// - Optional `initial_end_offset` flow-control check (`initial_max_stream_data` and `recv_fc`)
    ///   **before** mutating `self.streams` or advancing `next_peer_*_index`.
    ///
    /// Returns `Ok(true)` if `stream_id` is open in `self.streams`, or `Ok(false)` if `stream_id`
    /// was already opened and subsequently closed/reset (preventing stream resurrection).
    fn ensure_stream_for_peer_frame(
        &mut self,
        stream_id: StreamId,
        initial_end_offset: Option<u64>,
        initial_max_stream_data: u64,
    ) -> Result<bool, MuxError> {
        if self.streams.contains_key(&stream_id) {
            return Ok(true);
        }

        let idx = stream_id.index();
        if !self.is_peer_initiated(stream_id) {
            // Locally-initiated stream: must have been opened by us previously (`idx < next_local_*`).
            let next_local = if stream_id.is_bidi() {
                self.next_local_bidi_index
            } else {
                self.next_local_uni_index
            };
            if idx < next_local {
                // Already closed/reset locally; do not resurrect.
                return Ok(false);
            }
            return Err(MuxError::InvalidStreamState);
        }

        let (next_peer, max_allowed) = if stream_id.is_bidi() {
            (self.next_peer_bidi_index, self.local_max_streams_bidi)
        } else {
            (self.next_peer_uni_index, self.local_max_streams_uni)
        };

        if idx >= max_allowed {
            return Err(MuxError::StreamLimitReached);
        }
        if idx < next_peer {
            // Previously opened peer stream that has already been closed/reset/evicted; ignore late frame.
            return Ok(false);
        }

        let to_open_u64 = idx - next_peer + 1;
        let to_open = usize::try_from(to_open_u64).map_err(|_| MuxError::StreamLimitReached)?;
        if self.streams.len().saturating_add(to_open) > self.limits.max_concurrent_streams {
            return Err(MuxError::StreamLimitReached);
        }

        // Validate flow control BEFORE inserting any stream entries so failed frames cannot pollute `streams`.
        if let Some(end_off) = initial_end_offset {
            if end_off > initial_max_stream_data || !self.recv_fc.can_receive_delta(end_off) {
                return Err(MuxError::FlowControlViolation);
            }
        }

        let peer_bit = if self.is_client { 1u64 } else { 0u64 };
        let dir_bit = if stream_id.is_bidi() { 0u64 } else { 0x02u64 };
        let max_q = self.limits.max_rx_queued_packets_per_stream;

        for i in next_peer..=idx {
            let sid = StreamId((i << 2) | dir_bit | peer_bit);
            let mut st = StreamState::new(
                sid,
                StreamPriority::NORMAL,
                initial_max_stream_data,
                if sid.is_bidi() {
                    initial_max_stream_data
                } else {
                    0
                },
                max_q,
            );
            if sid.is_uni() {
                // Peer-initiated unidirectional stream has no local send half.
                st.fin_sent = true;
                st.send_stopped = true;
            }
            self.streams.insert(sid, st);
        }

        if stream_id.is_bidi() {
            self.next_peer_bidi_index = idx + 1;
        } else {
            self.next_peer_uni_index = idx + 1;
        }
        Ok(true)
    }

    fn on_stream_removed(&mut self, stream_id: StreamId) {
        if stream_id.is_client_initiated() != self.is_client {
            if stream_id.is_bidi() {
                self.local_max_streams_bidi = self.local_max_streams_bidi.saturating_add(1);
                self.pending_max_streams_bidi = true;
            } else {
                self.local_max_streams_uni = self.local_max_streams_uni.saturating_add(1);
                self.pending_max_streams_uni = true;
            }
        }
    }
}

/// Standalone QUIC stream multiplexer over abstracted pool packets and links.
pub struct QuicMux<P: PacketPool> {
    pool: P,
    limits: MuxLimits,
    device_capacity: usize,
    device_max_rx_packets: usize,
    associations: MuxMap<AssociationId, AssociationState<P::Packet>>,
}

impl<P: PacketPool> QuicMux<P> {
    /// Create a new [`QuicMux`] with `pool` and `limits`.
    pub fn new(pool: P, limits: MuxLimits) -> Self {
        let device_max_rx_packets = limits.max_device_rx_packets;
        Self {
            pool,
            limits,
            device_capacity: usize::MAX,
            device_max_rx_packets,
            associations: MuxMap::new(),
        }
    }

    /// Reference to the underlying packet pool.
    #[inline]
    pub const fn pool(&self) -> &P {
        &self.pool
    }

    /// Register a new association (`is_client` determines local stream ID parity: `0` for client, `1` for server).
    pub fn add_association(
        &mut self,
        assoc: AssociationId,
        is_client: bool,
    ) -> Result<(), MuxError> {
        if self.associations.contains_key(&assoc) {
            return Err(MuxError::DuplicateAssociation);
        }
        self.associations
            .insert(assoc, AssociationState::new(is_client, &self.limits));
        Ok(())
    }

    /// Remove an association, releasing all buffered `PoolPacket` leases and notifying open streams.
    pub fn remove_association(
        &mut self,
        assoc: AssociationId,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) {
        if let Some(mut state) = self.associations.remove(&assoc) {
            for (stream_id, mut stream) in core::mem::take(&mut state.streams) {
                let delivered = stream.rx.next_offset();
                stream.rx.clear();
                if !stream.rx.is_fin_delivered() {
                    cb.on_stream_closed(
                        assoc,
                        stream_id,
                        StreamCloseReason::AssociationClosed {
                            delivered_offset: delivered,
                        },
                    );
                }
            }
        }
    }

    /// Update global device send capacity (`0` throttles all outgoing stream writes and pauses
    /// automatic receive-window slides). Fires `on_device_writable` when recovering from `0`.
    pub fn set_device_capacity(
        &mut self,
        available_bytes: usize,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) {
        let was_zero = self.device_capacity == 0;
        self.device_capacity = available_bytes;
        if was_zero && available_bytes > 0 {
            cb.on_device_writable();
        }
    }

    /// Current global device capacity budget in bytes.
    #[inline]
    pub const fn device_capacity(&self) -> usize {
        self.device_capacity
    }

    /// Current dynamic device-wide limit on retained RX out-of-order `PoolPacket` chunks.
    #[inline]
    pub const fn device_rx_packet_limit(&self) -> usize {
        self.device_max_rx_packets
    }

    /// Total out-of-order / paused RX `PoolPacket` chunks currently retained across all associations.
    pub fn total_rx_queued_packets(&self) -> usize {
        self.associations
            .values()
            .map(AssociationState::rx_queued_packets)
            .sum()
    }

    /// Total out-of-order / paused RX `PoolPacket` chunks currently retained in `assoc`.
    pub fn association_rx_queued_packets(&self, assoc: AssociationId) -> Option<usize> {
        self.associations
            .get(&assoc)
            .map(AssociationState::rx_queued_packets)
    }

    /// Dynamically adjust the device-wide limit on retained RX out-of-order packets based on load.
    ///
    /// If the new limit is lower than `total_rx_queued_packets()`, immediately evicts and resets
    /// (`RST` / `StreamCloseReason::ResourcePressure`) the lowest-priority stream(s) holding RX
    /// packets until usage is within `max_packets`. Returns the number of streams terminated.
    pub fn set_device_rx_packet_limit(
        &mut self,
        max_packets: usize,
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) -> usize {
        self.device_max_rx_packets = max_packets;
        let mut evicted = 0;
        while self.total_rx_queued_packets() > self.device_max_rx_packets {
            let Some((victim_assoc, victim_stream)) = self.select_device_victim_stream(None) else {
                break;
            };
            if self.abort_stream_under_pressure(victim_assoc, victim_stream, egress, cb) {
                evicted += 1;
            } else {
                break;
            }
        }
        evicted
    }

    /// Dynamically adjust the per-association limits for `assoc` based on load.
    ///
    /// Updates `max_concurrent_streams`, `max_rx_queued_packets`, and `max_rx_queued_packets_per_stream`.
    /// Any stream exceeding the new per-stream limit or the new association RX packet limit is
    /// evicted in lowest-priority order (`RST` / `StreamCloseReason::ResourcePressure`).
    /// Returns the number of streams terminated.
    pub fn set_association_limits(
        &mut self,
        assoc: AssociationId,
        limits: AssociationLimits,
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) -> Result<usize, MuxError> {
        let mut over_per_stream = Vec::new();
        {
            let state = self
                .associations
                .get_mut(&assoc)
                .ok_or(MuxError::UnknownAssociation)?;
            state.limits = limits;
            for (&sid, st) in &mut state.streams {
                st.rx.set_max_chunks(limits.max_rx_queued_packets_per_stream);
                if st.rx.queued_chunks() > limits.max_rx_queued_packets_per_stream {
                    over_per_stream.push(sid);
                }
            }
        }

        let mut evicted = 0;
        for sid in over_per_stream {
            if self.abort_stream_under_pressure(assoc, sid, egress, cb) {
                evicted += 1;
            }
        }

        while self
            .association_rx_queued_packets(assoc)
            .unwrap_or(0)
            > limits.max_rx_queued_packets
        {
            let Some(victim_stream) = self.select_assoc_victim_stream(assoc, None) else {
                break;
            };
            if self.abort_stream_under_pressure(assoc, victim_stream, egress, cb) {
                evicted += 1;
            } else {
                break;
            }
        }
        Ok(evicted)
    }

    /// Terminate/RST `(assoc, stream_id)` due to RX out-of-order or TX retransmit resource pressure:
    ///
    /// 1. Drops all retained RX `PoolPacket` leases and returns unconsumed stream bytes to
    ///    association-level `MAX_DATA` flow control.
    /// 2. Calls `egress.on_stream_aborted(assoc, stream_id)` so the association layer drops any
    ///    retained unACKed TX packets for that stream.
    /// 3. Best-effort sends `RESET_STREAM` and/or `STOP_SENDING` control frames to the peer.
    /// 4. Invokes `cb.on_stream_closed(assoc, stream_id, StreamCloseReason::ResourcePressure { delivered_offset })`.
    pub fn abort_stream_under_pressure(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) -> bool {
        let allow_slide = self.device_capacity > 0;
        let (delivered_offset, final_size, send_reset, send_stop) = {
            let Some(state) = self.associations.get_mut(&assoc) else {
                return false;
            };
            let has_send = state.has_local_send(stream_id);
            let has_recv = state.has_local_recv(stream_id);
            let Some(st) = state.retire_stream(stream_id, allow_slide) else {
                return false;
            };
            (
                st.rx.next_offset(),
                st.send_offset,
                has_send && !st.fin_sent,
                has_recv && !st.recv_reset && !st.rx.is_fin_delivered(),
            )
        };

        egress.on_stream_aborted(assoc, stream_id);
        self.send_stream_abort_frames(
            assoc,
            stream_id,
            final_size,
            RESOURCE_PRESSURE_ERROR_CODE,
            send_reset,
            send_stop,
            egress,
        );
        let _ = self.flush_control(assoc, egress);
        cb.on_stream_closed(
            assoc,
            stream_id,
            StreamCloseReason::ResourcePressure { delivered_offset },
        );
        true
    }

    /// Cleanly remove a finished stream `(assoc, stream_id)`, reclaim any unconsumed RX window
    /// credit, and replenish `MAX_STREAMS` credit if the stream was peer-initiated.
    pub fn close_stream(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        egress: &mut impl AssociationEgress<P::Packet>,
    ) -> bool {
        let allow_slide = self.device_capacity > 0;
        let Some(state) = self.associations.get_mut(&assoc) else {
            return false;
        };
        if state.retire_stream(stream_id, allow_slide).is_none() {
            return false;
        }
        let _ = self.flush_control(assoc, egress);
        true
    }

    /// Locally reset and stop `(assoc, stream_id)` with application `error_code`.
    pub fn reset_stream(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        error_code: u64,
        egress: &mut impl AssociationEgress<P::Packet>,
    ) -> bool {
        let allow_slide = self.device_capacity > 0;
        let (final_size, send_reset, send_stop) = {
            let Some(state) = self.associations.get_mut(&assoc) else {
                return false;
            };
            let has_send = state.has_local_send(stream_id);
            let has_recv = state.has_local_recv(stream_id);
            let Some(st) = state.retire_stream(stream_id, allow_slide) else {
                return false;
            };
            (
                st.send_offset,
                has_send && !st.fin_sent,
                has_recv && !st.recv_reset && !st.rx.is_fin_delivered(),
            )
        };
        egress.on_stream_aborted(assoc, stream_id);
        self.send_stream_abort_frames(
            assoc,
            stream_id,
            final_size,
            error_code,
            send_reset,
            send_stop,
            egress,
        );
        let _ = self.flush_control(assoc, egress);
        true
    }

    /// Locally stop reading `(assoc, stream_id)` and send `STOP_SENDING(error_code)` to the peer,
    /// leaving the local send half open if still active on a bidirectional stream.
    pub fn stop_sending(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        error_code: u64,
        egress: &mut impl AssociationEgress<P::Packet>,
    ) -> bool {
        let allow_slide = self.device_capacity > 0;
        let should_send = {
            let Some(state) = self.associations.get_mut(&assoc) else {
                return false;
            };
            if !state.has_local_recv(stream_id) {
                return false;
            }
            let has_send = state.has_local_send(stream_id);
            let Some(st) = state.streams.get_mut(&stream_id) else {
                return false;
            };
            if st.recv_reset || st.rx.is_fin_delivered() {
                return false;
            }
            st.recv_reset = true;
            st.rx.clear();
            let unconsumed = st
                .recv_fc
                .highest_received()
                .saturating_sub(st.recv_fc.consumed());
            if unconsumed > 0 {
                st.recv_fc.on_consumed(unconsumed, false);
                state.recv_fc.on_consumed(unconsumed, allow_slide);
            }
            if !has_send || st.fin_sent || st.send_stopped {
                state.retire_stream(stream_id, allow_slide);
            }
            true
        };
        if should_send {
            self.send_stream_abort_frames(assoc, stream_id, 0, error_code, false, true, egress);
            let _ = self.flush_control(assoc, egress);
        }
        should_send
    }

    /// Send a transport-level (`0x1c`, `is_application == false`) or application-level (`0x1d`,
    /// `is_application == true`) `CONNECTION_CLOSE` frame on `assoc`.
    pub fn close_association(
        &mut self,
        assoc: AssociationId,
        is_application: bool,
        error_code: u64,
        frame_type: u64,
        egress: &mut impl AssociationEgress<P::Packet>,
    ) -> Result<(), MuxError> {
        if !self.associations.contains_key(&assoc) {
            return Err(MuxError::UnknownAssociation);
        }
        if egress.max_writable_frame_len(assoc) < 28 {
            return Ok(());
        }
        let mut pkt = self.pool.alloc().map_err(MuxError::Pool)?;
        let mut buf = [0u8; 32];
        let n = encode_control_frame(
            &Frame::ConnectionClose {
                is_application,
                error_code,
                frame_type,
            },
            &mut buf,
        )
        .map_err(MuxError::Wire)?;
        pkt.append(&buf[..n]).map_err(MuxError::Pool)?;
        let _ = egress.send_packet(
            TxPacketMeta {
                association: assoc,
                stream_id: None,
                priority: StreamPriority::CRITICAL,
                retransmittable: false,
            },
            pkt,
        );
        Ok(())
    }

    /// Notify `quic-mux` that a link or connection window on `assoc` became ready for sending.
    pub fn on_association_ready(
        &mut self,
        assoc: AssociationId,
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) {
        let _ = self.flush_control(assoc, egress);
        if let Some(state) = self.associations.get(&assoc) {
            let avail = state.send_fc.available();
            if avail > 0 && self.device_capacity > 0 && egress.max_writable_frame_len(assoc) > 0 {
                cb.on_association_writable(assoc, avail);
            }
        }
    }

    /// Open a new locally-initiated stream on `assoc` with [`StreamPriority::NORMAL`].
    pub fn open_stream(&mut self, assoc: AssociationId, bidi: bool) -> Result<StreamId, MuxError> {
        self.open_stream_with_priority(assoc, bidi, StreamPriority::NORMAL)
    }

    /// Open a new locally-initiated stream on `assoc` with explicit `priority`.
    pub fn open_stream_with_priority(
        &mut self,
        assoc: AssociationId,
        bidi: bool,
        priority: StreamPriority,
    ) -> Result<StreamId, MuxError> {
        let state = self
            .associations
            .get_mut(&assoc)
            .ok_or(MuxError::UnknownAssociation)?;
        if state.streams.len() >= state.limits.max_concurrent_streams {
            return Err(MuxError::StreamLimitReached);
        }
        let initiator_bit = if state.is_client { 0u64 } else { 1u64 };
        let stream_id = if bidi {
            if state.next_local_bidi_index >= state.peer_max_streams_bidi {
                return Err(MuxError::StreamLimitReached);
            }
            let idx = state.next_local_bidi_index;
            state.next_local_bidi_index += 1;
            StreamId((idx << 2) | initiator_bit)
        } else {
            if state.next_local_uni_index >= state.peer_max_streams_uni {
                return Err(MuxError::StreamLimitReached);
            }
            let idx = state.next_local_uni_index;
            state.next_local_uni_index += 1;
            StreamId((idx << 2) | 0x02 | initiator_bit)
        };
        let mut st = StreamState::new(
            stream_id,
            priority,
            if bidi {
                self.limits.initial_max_stream_data
            } else {
                0
            },
            self.limits.initial_max_stream_data,
            state.limits.max_rx_queued_packets_per_stream,
        );
        if !bidi {
            // Locally-initiated unidirectional stream has no local receive half.
            st.recv_reset = true;
        }
        state.streams.insert(stream_id, st);
        Ok(stream_id)
    }

    /// Dynamically update the priority of `stream` on `assoc`.
    pub fn set_stream_priority(
        &mut self,
        assoc: AssociationId,
        stream: StreamId,
        priority: StreamPriority,
    ) -> Result<(), MuxError> {
        let state = self
            .associations
            .get_mut(&assoc)
            .ok_or(MuxError::UnknownAssociation)?;
        let st = state
            .streams
            .get_mut(&stream)
            .ok_or(MuxError::UnknownStream)?;
        st.priority = priority;
        Ok(())
    }

    /// Query the current priority of `stream` on `assoc`.
    pub fn stream_priority(
        &self,
        assoc: AssociationId,
        stream: StreamId,
    ) -> Result<StreamPriority, MuxError> {
        let state = self
            .associations
            .get(&assoc)
            .ok_or(MuxError::UnknownAssociation)?;
        let st = state.streams.get(&stream).ok_or(MuxError::UnknownStream)?;
        Ok(st.priority)
    }

    /// Query the current send capacity for `stream` on `assoc`.
    pub fn stream_send_capacity(
        &self,
        assoc: AssociationId,
        stream: StreamId,
        egress: &impl AssociationEgress<P::Packet>,
    ) -> Result<StreamSendCapacity, MuxError> {
        let state = self
            .associations
            .get(&assoc)
            .ok_or(MuxError::UnknownAssociation)?;
        if !state.has_local_send(stream) {
            return Err(MuxError::InvalidStreamState);
        }
        let st = state.streams.get(&stream).ok_or(MuxError::UnknownStream)?;
        if st.send_stopped {
            return Err(MuxError::StreamReset);
        }
        let assoc_win = state.send_fc.available();
        let stream_win = st.send_fc.available();
        let max_frame = egress.max_writable_frame_len(assoc);
        // Reserve up to 32 bytes for STREAM header + piggybacked MAX_DATA / MAX_STREAM_DATA.
        let link_payload = max_frame
            .saturating_sub(32)
            .min(self.pool.max_payload());
        let max_chunk_bytes = self
            .device_capacity
            .min(usize::try_from(assoc_win).unwrap_or(usize::MAX))
            .min(usize::try_from(stream_win).unwrap_or(usize::MAX))
            .min(link_payload);
        Ok(StreamSendCapacity {
            max_chunk_bytes,
            stream_window: stream_win,
            association_window: assoc_win,
            can_send_now: self.device_capacity > 0
                && max_frame > 32
                && assoc_win > 0
                && stream_win > 0,
        })
    }

    /// Send stream data on `(assoc, stream)`:
    ///
    /// - **`TxStreamData::Packet(pkt)` (Zero-Copy):** Caller placed payload at `pkt.range()`
    ///   (starting at `>= pool.headroom()`). `quic-mux` encodes any pending `MAX_DATA` /
    ///   `MAX_STREAM_DATA` control frames and the `STREAM` frame header directly in front of
    ///   `pkt.range().start` in-place, then passes ownership of `pkt` to
    ///   `egress.send_packet(tx_meta, pkt)` so the association/link layer can select the link
    ///   and retain `pkt` for Selective ACK / retransmission.
    ///   If refused (`Busy` or `FlowControl`), `pkt.range()` is restored to the original payload
    ///   range and returned in `MuxSendError`.
    /// - **`TxStreamData::Bytes(slice)`:** Allocates a pool packet at `headroom`, copies `slice`
    ///   into the payload window, and sends via the same path.
    pub fn write_stream<'a>(
        &mut self,
        assoc: AssociationId,
        stream: StreamId,
        data: TxStreamData<'a, P::Packet>,
        fin: bool,
        egress: &mut impl AssociationEgress<P::Packet>,
    ) -> Result<usize, MuxSendError<P::Packet>> {
        let payload_len = data.len();
        let (mut packet, caller_owned, orig_range) = match data {
            TxStreamData::Packet(pkt) => {
                let r = pkt.range();
                (pkt, true, r)
            }
            TxStreamData::Bytes(slice) => {
                if payload_len > self.pool.max_payload() {
                    return Err(MuxSendError::PacketTooLarge {
                        packet: None,
                        max_payload: self.pool.max_payload(),
                    });
                }
                let mut pkt = self.pool.alloc().map_err(|e| MuxSendError::Error {
                    packet: None,
                    error: MuxError::Pool(e),
                })?;
                if let Err(e) = pkt.append(slice) {
                    return Err(MuxSendError::Error {
                        packet: None,
                        error: MuxError::Pool(e),
                    });
                }
                let r = pkt.range();
                (pkt, false, r)
            }
        };

        let ret_pkt = |pkt: P::Packet| if caller_owned { Some(pkt) } else { None };

        if payload_len > 0 && self.device_capacity < payload_len {
            return Err(MuxSendError::FlowControl(ret_pkt(packet)));
        }

        let Some(state) = self.associations.get_mut(&assoc) else {
            return Err(MuxSendError::Error {
                packet: ret_pkt(packet),
                error: MuxError::UnknownAssociation,
            });
        };
        if !state.has_local_send(stream) {
            return Err(MuxSendError::Error {
                packet: ret_pkt(packet),
                error: MuxError::InvalidStreamState,
            });
        }
        let Some(st) = state.streams.get_mut(&stream) else {
            return Err(MuxSendError::Error {
                packet: ret_pkt(packet),
                error: MuxError::UnknownStream,
            });
        };
        if st.send_stopped {
            return Err(MuxSendError::Error {
                packet: ret_pkt(packet),
                error: MuxError::StreamReset,
            });
        }
        if st.fin_sent {
            return Err(MuxSendError::Error {
                packet: ret_pkt(packet),
                error: MuxError::StreamFinished,
            });
        }
        if (payload_len as u64) > state.send_fc.available()
            || (payload_len as u64) > st.send_fc.available()
        {
            return Err(MuxSendError::FlowControl(ret_pkt(packet)));
        }

        let max_frame = egress.max_writable_frame_len(assoc);
        if max_frame == 0 {
            return Err(MuxSendError::Busy(ret_pkt(packet)));
        }

        // Build prefix header: [optional MAX_DATA | optional MAX_STREAM_DATA | STREAM header]
        let mut hdr_buf = [0u8; 48];
        let mut hdr_len = 0usize;
        let mut piggybacked_max_data = false;
        let mut piggybacked_max_stream_data = false;

        if let Some(max_data) = state.recv_fc.peek_pending_update() {
            if let Ok(n) = encode_control_frame(&Frame::MaxData(max_data), &mut hdr_buf[hdr_len..])
            {
                hdr_len += n;
                piggybacked_max_data = true;
            }
        }
        if let Some(max_stream_data) = st.recv_fc.peek_pending_update() {
            if let Ok(n) = encode_control_frame(
                &Frame::MaxStreamData {
                    stream_id: stream,
                    max_stream_data,
                },
                &mut hdr_buf[hdr_len..],
            ) {
                hdr_len += n;
                piggybacked_max_stream_data = true;
            }
        }

        let stream_hdr_len = match encode_stream_header(
            stream,
            st.send_offset,
            payload_len,
            fin,
            true,
            &mut hdr_buf[hdr_len..],
        ) {
            Ok(n) => n,
            Err(e) => {
                return Err(MuxSendError::Error {
                    packet: ret_pkt(packet),
                    error: MuxError::Wire(e),
                });
            }
        };
        hdr_len += stream_hdr_len;

        if hdr_len + payload_len > max_frame {
            return Err(MuxSendError::PacketTooLarge {
                packet: ret_pkt(packet),
                max_payload: max_frame.saturating_sub(hdr_len),
            });
        }

        if let Err(e) = packet.prepend(&hdr_buf[..hdr_len]) {
            return Err(MuxSendError::Error {
                packet: ret_pkt(packet),
                error: MuxError::Pool(e),
            });
        }

        let tx_meta = TxPacketMeta {
            association: assoc,
            stream_id: Some(stream),
            priority: st.priority,
            retransmittable: true,
        };

        match egress.send_packet(tx_meta, packet) {
            Ok(()) => {
                st.send_offset = st.send_offset.saturating_add(payload_len as u64);
                st.send_fc.commit_send(payload_len as u64);
                state.send_fc.commit_send(payload_len as u64);
                if fin {
                    st.fin_sent = true;
                }
                if piggybacked_max_data {
                    state.recv_fc.clear_pending_update();
                }
                if piggybacked_max_stream_data {
                    st.recv_fc.clear_pending_update();
                }
                if self.device_capacity != usize::MAX {
                    self.device_capacity = self.device_capacity.saturating_sub(payload_len);
                }
                Ok(payload_len)
            }
            Err(LinkSendError::Busy(mut pkt)) => {
                let _ = pkt.set_range(orig_range);
                Err(MuxSendError::Busy(ret_pkt(pkt)))
            }
            Err(LinkSendError::TooLarge {
                packet: mut pkt,
                max_frame_len,
            }) => {
                let _ = pkt.set_range(orig_range);
                Err(MuxSendError::PacketTooLarge {
                    packet: ret_pkt(pkt),
                    max_payload: max_frame_len.saturating_sub(hdr_len),
                })
            }
            Err(LinkSendError::NoAssociation(mut pkt)) => {
                let _ = pkt.set_range(orig_range);
                Err(MuxSendError::Error {
                    packet: ret_pkt(pkt),
                    error: MuxError::UnknownAssociation,
                })
            }
        }
    }

    /// Release receive flow-control credit after a handler that returned
    /// [`RxOutcome::RetainedPendingCredit`] finishes forwarding or consuming its owned `PoolPacket`.
    pub fn release_stream_credit(
        &mut self,
        assoc: AssociationId,
        stream: StreamId,
        consumed_bytes: usize,
        egress: &mut impl AssociationEgress<P::Packet>,
    ) -> Result<(), MuxError> {
        let allow_slide = self.device_capacity > 0;
        let state = self
            .associations
            .get_mut(&assoc)
            .ok_or(MuxError::UnknownAssociation)?;
        let st = state
            .streams
            .get_mut(&stream)
            .ok_or(MuxError::UnknownStream)?;
        if st.recv_reset {
            return Ok(());
        }
        let max_releasable = st
            .recv_fc
            .highest_received()
            .saturating_sub(st.recv_fc.consumed());
        let to_release = (consumed_bytes as u64).min(max_releasable);
        if to_release > 0 {
            st.recv_fc.on_consumed(to_release, allow_slide);
            state.recv_fc.on_consumed(to_release, allow_slide);
            let _ = self.flush_control(assoc, egress);
        }
        Ok(())
    }

    /// Flush standalone `MAX_DATA`, `MAX_STREAM_DATA`, and `MAX_STREAMS` control frames if pending.
    pub fn flush_control(
        &mut self,
        assoc: AssociationId,
        egress: &mut impl AssociationEgress<P::Packet>,
    ) -> Result<bool, MuxError> {
        let state = self
            .associations
            .get_mut(&assoc)
            .ok_or(MuxError::UnknownAssociation)?;
        let has_assoc_update = state.recv_fc.has_pending_update();
        let has_max_streams = state.pending_max_streams_bidi || state.pending_max_streams_uni;
        let has_stream_update = state
            .streams
            .values()
            .any(|s| s.recv_fc.has_pending_update());
        if !has_assoc_update && !has_max_streams && !has_stream_update {
            return Ok(false);
        }
        let max_frame = egress.max_writable_frame_len(assoc);
        if max_frame < 16 {
            return Ok(false);
        }

        let mut pkt = self.pool.alloc().map_err(MuxError::Pool)?;
        let mut buf = [0u8; 96];
        let mut written = 0usize;
        let mut sent_assoc = false;
        let mut sent_bidi_limit = false;
        let mut sent_uni_limit = false;
        let mut sent_streams = [StreamId(0); 32];
        let mut sent_streams_len = 0usize;

        if let Some(max_data) = state.recv_fc.peek_pending_update() {
            let n = encode_control_frame(&Frame::MaxData(max_data), &mut buf[written..])
                .map_err(MuxError::Wire)?;
            written += n;
            sent_assoc = true;
        }
        if state.pending_max_streams_bidi && written + 10 <= buf.len().min(max_frame) {
            let n = encode_control_frame(
                &Frame::MaxStreamsBidi(state.local_max_streams_bidi),
                &mut buf[written..],
            )
            .map_err(MuxError::Wire)?;
            written += n;
            sent_bidi_limit = true;
        }
        if state.pending_max_streams_uni && written + 10 <= buf.len().min(max_frame) {
            let n = encode_control_frame(
                &Frame::MaxStreamsUni(state.local_max_streams_uni),
                &mut buf[written..],
            )
            .map_err(MuxError::Wire)?;
            written += n;
            sent_uni_limit = true;
        }
        for (&sid, st) in &state.streams {
            if let Some(max_stream_data) = st.recv_fc.peek_pending_update() {
                if sent_streams_len >= sent_streams.len() || written + 18 > buf.len().min(max_frame)
                {
                    break;
                }
                let n = encode_control_frame(
                    &Frame::MaxStreamData {
                        stream_id: sid,
                        max_stream_data,
                    },
                    &mut buf[written..],
                )
                .map_err(MuxError::Wire)?;
                written += n;
                sent_streams[sent_streams_len] = sid;
                sent_streams_len += 1;
            }
        }
        if written == 0 {
            return Ok(false);
        }
        pkt.append(&buf[..written]).map_err(MuxError::Pool)?;
        let tx_meta = TxPacketMeta {
            association: assoc,
            stream_id: None,
            priority: StreamPriority::CRITICAL,
            retransmittable: true,
        };
        match egress.send_packet(tx_meta, pkt) {
            Ok(()) => {
                if sent_assoc {
                    state.recv_fc.clear_pending_update();
                }
                if sent_bidi_limit {
                    state.pending_max_streams_bidi = false;
                }
                if sent_uni_limit {
                    state.pending_max_streams_uni = false;
                }
                for &sid in &sent_streams[..sent_streams_len] {
                    if let Some(st) = state.streams.get_mut(&sid) {
                        st.recv_fc.clear_pending_update();
                    }
                }
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    /// Process an inbound packet for `meta.association`.
    ///
    /// ### Packet-Atomic Validation & Exact Wire-Order Execution
    /// - **Packet-atomic malformed frame policy:** Pass 1 validates every frame in `packet` with
    ///   [`decode_frame`] before mutating any association or stream state. A single malformed or
    ///   unsupported frame anywhere in `packet` rejects the entire packet with `Err(MuxError::Wire(_))`
    ///   without partial state changes.
    /// - **Exact wire-order execution:** Pass 2 executes control frames (`MAX_DATA`,
    ///   `MAX_STREAM_DATA`, `MAX_STREAMS`, `RESET_STREAM`, `STOP_SENDING`, `CONNECTION_CLOSE`) and
    ///   `STREAM` frames strictly in the order they appear in `packet` (for example, `[STREAM,
    ///   RESET_STREAM]` delivers the `STREAM` bytes before applying the reset, whereas
    ///   `[RESET_STREAM, STREAM]` resets first and ignores the trailing `STREAM`).
    /// - **Zero heap allocations on the hot path:** Control packets, single-`STREAM` packets (with
    ///   optional leading/trailing control frames), multi-`STREAM` packets `<= 1/2 MTU`, and
    ///   coalesced packets with one `> 1/2 MTU` `STREAM` frame plus up to 1 KiB of trailing frames
    ///   all execute without allocating any per-packet `Vec` or `Box` on the heap:
    ///   - **Single-stream packet:** Transfers exclusive ownership of `packet` (`is_unique() == true`)
    ///     via `RxStreamChunk::from_packet` directly to `cb.on_stream_data` when in-order, or moves
    ///     `packet` into `OrderedStream` when out-of-order.
    ///   - **Multi-frame packet with a frame `> 1/2 MTU`:** Executes earlier frames from borrowed
    ///     slices, copies any trailing frames (`<= 1/2 MTU`) onto a stack buffer (falling back to
    ///     `Vec` only on jumbo MTUs where trailing bytes exceed 1024 B), moves exclusive `PoolPacket`
    ///     ownership of `packet` into the `> 1/2 MTU` frame, and then executes the trailing frames.
    ///   - **Multi-frame packet where all frames are `<= 1/2 MTU`:** Executes every frame in wire
    ///     order from borrowed slices (zero allocations when in-order) and drops `packet` at the end.
    pub fn receive_packet(
        &mut self,
        meta: RxMeta,
        packet: P::Packet,
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) -> Result<(), MuxError> {
        if !self.associations.contains_key(&meta.association) {
            return Err(MuxError::UnknownAssociation);
        }

        let pkt_range = packet.range();
        let half_mtu = self.pool.max_payload() / 2;
        let mut stream_count = 0usize;
        let mut single_span: (usize, usize) = (0, 0);
        let mut single_sf = StreamFrameRange {
            stream_id: StreamId(0),
            offset: 0,
            fin: false,
            payload_range: 0..0,
        };
        let mut owner_span: Option<(usize, usize, StreamFrameRange)> = None;

        // Pass 1: Packet-atomic wire validation (zero allocations, zero state mutations).
        {
            let pkt_bytes = packet.bytes();
            let mut offset = 0usize;
            while offset < pkt_bytes.len() {
                let frame_start = offset;
                let (frame, next_offset) =
                    decode_frame(pkt_bytes, offset).map_err(MuxError::Wire)?;
                offset = next_offset;
                if let Frame::Stream(mut sf) = frame {
                    sf.payload_range = (pkt_range.start + sf.payload_range.start)
                        ..(pkt_range.start + sf.payload_range.end);
                    if stream_count == 0 {
                        single_span = (frame_start, next_offset);
                        single_sf = sf.clone();
                    }
                    stream_count += 1;
                    if sf.payload_range.len() > half_mtu {
                        let replace = owner_span.as_ref().is_none_or(|(_, _, prev)| {
                            sf.payload_range.len() > prev.payload_range.len()
                        });
                        if replace {
                            owner_span = Some((frame_start, next_offset, sf));
                        }
                    }
                }
            }
        }

        let owned_target = if stream_count == 1 {
            Some((single_span.0, single_span.1, single_sf))
        } else if stream_count > 1 {
            owner_span
        } else {
            None
        };

        // Pass 2: Execute frames in exact wire order.
        if let Some((own_start, own_end, own_sf)) = owned_target {
            if own_start > 0 {
                let prefix = &packet.bytes()[..own_start];
                self.execute_borrowed_frames(meta, prefix, egress, cb)?;
            }
            let total_len = packet.bytes().len();
            let tail_len = total_len - own_end;
            if tail_len == 0 {
                self.handle_stream_frame_owned(meta, own_sf, packet, egress, cb)?;
            } else if tail_len <= 1024 {
                let mut tail_stack = [0u8; 1024];
                tail_stack[..tail_len].copy_from_slice(&packet.bytes()[own_end..]);
                self.handle_stream_frame_owned(meta, own_sf, packet, egress, cb)?;
                self.execute_borrowed_frames(meta, &tail_stack[..tail_len], egress, cb)?;
            } else {
                let mut tail_heap = Vec::with_capacity(tail_len);
                tail_heap.extend_from_slice(&packet.bytes()[own_end..]);
                self.handle_stream_frame_owned(meta, own_sf, packet, egress, cb)?;
                self.execute_borrowed_frames(meta, &tail_heap, egress, cb)?;
            }
        } else {
            self.execute_borrowed_frames(meta, packet.bytes(), egress, cb)?;
            drop(packet);
        }

        let _ = self.flush_control(meta.association, egress);
        Ok(())
    }

    fn execute_borrowed_frames(
        &mut self,
        meta: RxMeta,
        frames_buf: &[u8],
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) -> Result<(), MuxError> {
        let mut offset = 0usize;
        while offset < frames_buf.len() {
            let (frame, next_offset) = decode_frame(frames_buf, offset).map_err(MuxError::Wire)?;
            offset = next_offset;
            match frame {
                Frame::Padding | Frame::Ping => {}
                Frame::Stream(sf) => {
                    let slice = &frames_buf[sf.payload_range.clone()];
                    self.handle_stream_frame_slice(meta, sf, slice, egress, cb)?;
                }
                ctrl => {
                    self.handle_control_frame(meta.association, ctrl, egress, cb)?;
                }
            }
        }
        Ok(())
    }

    /// Resume delivery of buffered stream chunks after a consumer that returned a partial
    /// `RxOutcome::Partial` (or partial `Consumed(n)`) is ready to accept more bytes.
    pub fn resume_stream(
        &mut self,
        assoc: AssociationId,
        stream: StreamId,
        now_us: u64,
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) -> Result<usize, MuxError> {
        {
            let state = self
                .associations
                .get_mut(&assoc)
                .ok_or(MuxError::UnknownAssociation)?;
            let st = state
                .streams
                .get_mut(&stream)
                .ok_or(MuxError::UnknownStream)?;
            st.rx.clear_pause();
        }
        let delivered = self.drain_in_order(assoc, stream, now_us, egress, cb)?;
        let _ = self.flush_control(assoc, egress);
        Ok(delivered)
    }

    /// Earliest deadline (in microseconds) at which an out-of-order stream gap will time out.
    pub fn next_deadline(&self) -> Option<u64> {
        let timeout = self.limits.gap_timeout_us;
        self.associations
            .values()
            .flat_map(|a| a.streams.values())
            .filter_map(|s| s.rx.gap_deadline_us(timeout))
            .min()
    }

    /// Check all active streams for expired out-of-order middle-frame gaps at `now_us`.
    ///
    /// For each expired stream:
    /// 1. Releases buffered out-of-order `PoolPacket` leases and returns unconsumed stream bytes
    ///    to association-level `MAX_DATA` flow control.
    /// 2. Notifies `egress.on_stream_aborted` and sends `RESET_STREAM` / `STOP_SENDING`
    ///    (`GAP_TIMEOUT_ERROR_CODE`) to the peer.
    /// 3. Calls `cb.on_stream_closed(assoc, stream_id, StreamCloseReason::GapTimeout { missing_offset })`.
    /// 4. Calls `cb.on_association_broken(assoc, AssociationBrokenReason::StreamGapTimeout { stream_id, missing_offset })`.
    ///
    /// Returns the number of broken streams reset.
    pub fn advance_time(
        &mut self,
        now_us: u64,
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) -> usize {
        let timeout = self.limits.gap_timeout_us;
        let allow_slide = self.device_capacity > 0;
        let mut expired = Vec::new();

        for (&assoc_id, state) in &self.associations {
            for (&stream_id, st) in &state.streams {
                if let Some(deadline) = st.rx.gap_deadline_us(timeout) {
                    if now_us >= deadline {
                        expired.push((assoc_id, stream_id, st.rx.next_offset()));
                    }
                }
            }
        }

        let count = expired.len();
        for (assoc_id, stream_id, missing_offset) in expired {
            let abort_info = self.associations.get_mut(&assoc_id).and_then(|state| {
                let has_send = state.has_local_send(stream_id);
                let has_recv = state.has_local_recv(stream_id);
                let st = state.retire_stream(stream_id, allow_slide)?;
                Some((
                    st.send_offset,
                    has_send && !st.fin_sent,
                    has_recv && !st.recv_reset && !st.rx.is_fin_delivered(),
                ))
            });
            if let Some((final_size, send_reset, send_stop)) = abort_info {
                egress.on_stream_aborted(assoc_id, stream_id);
                self.send_stream_abort_frames(
                    assoc_id,
                    stream_id,
                    final_size,
                    GAP_TIMEOUT_ERROR_CODE,
                    send_reset,
                    send_stop,
                    egress,
                );
                let _ = self.flush_control(assoc_id, egress);
            }
            cb.on_stream_closed(
                assoc_id,
                stream_id,
                StreamCloseReason::GapTimeout { missing_offset },
            );
            cb.on_association_broken(
                assoc_id,
                AssociationBrokenReason::StreamGapTimeout {
                    stream_id,
                    missing_offset,
                },
            );
        }
        count
    }

    fn handle_control_frame(
        &mut self,
        assoc: AssociationId,
        frame: Frame,
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) -> Result<(), MuxError> {
        let init_stream_max = self.limits.initial_max_stream_data;
        let allow_slide = self.device_capacity > 0;

        match frame {
            Frame::MaxData(new_max) => {
                let state = self
                    .associations
                    .get_mut(&assoc)
                    .ok_or(MuxError::UnknownAssociation)?;
                if state.send_fc.update_peer_max(new_max) {
                    let avail = state.send_fc.available();
                    cb.on_association_writable(assoc, avail);
                }
            }
            Frame::MaxStreamData {
                stream_id,
                max_stream_data,
            } => {
                let notify = {
                    let state = self
                        .associations
                        .get_mut(&assoc)
                        .ok_or(MuxError::UnknownAssociation)?;
                    if !state.has_local_send(stream_id) {
                        return Err(MuxError::InvalidStreamState);
                    }
                    if !state.ensure_stream_for_peer_frame(stream_id, None, init_stream_max)? {
                        return Ok(());
                    }
                    let st = state.streams.get_mut(&stream_id).unwrap();
                    st.send_fc.update_peer_max(max_stream_data) && !st.send_stopped
                };
                if notify {
                    if let Ok(cap) = self.stream_send_capacity(assoc, stream_id, egress) {
                        cb.on_stream_writable(assoc, stream_id, cap.max_chunk_bytes);
                    }
                }
            }
            Frame::MaxStreamsBidi(max) => {
                if max > (1u64 << 60) {
                    return Err(MuxError::FlowControlViolation);
                }
                let state = self
                    .associations
                    .get_mut(&assoc)
                    .ok_or(MuxError::UnknownAssociation)?;
                if max > state.peer_max_streams_bidi {
                    state.peer_max_streams_bidi = max;
                    let avail = state.send_fc.available();
                    cb.on_association_writable(assoc, avail);
                }
            }
            Frame::MaxStreamsUni(max) => {
                if max > (1u64 << 60) {
                    return Err(MuxError::FlowControlViolation);
                }
                let state = self
                    .associations
                    .get_mut(&assoc)
                    .ok_or(MuxError::UnknownAssociation)?;
                if max > state.peer_max_streams_uni {
                    state.peer_max_streams_uni = max;
                    let avail = state.send_fc.available();
                    cb.on_association_writable(assoc, avail);
                }
            }
            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                {
                    let state = self
                        .associations
                        .get_mut(&assoc)
                        .ok_or(MuxError::UnknownAssociation)?;
                    if !state.has_local_recv(stream_id) {
                        return Err(MuxError::InvalidStreamState);
                    }
                    if !state.ensure_stream_for_peer_frame(
                        stream_id,
                        Some(final_size),
                        init_stream_max,
                    )? {
                        return Ok(());
                    }
                    let has_send = state.has_local_send(stream_id);
                    let (newly, already_reset, can_retire) = {
                        let st = state.streams.get(&stream_id).unwrap();
                        if final_size < st.recv_fc.highest_received() {
                            return Err(MuxError::FlowControlViolation);
                        }
                        st.rx
                            .check_bounds(final_size, true)
                            .map_err(MuxError::Reassembly)?;
                        if !st.recv_fc.can_receive_end(final_size) {
                            return Err(MuxError::FlowControlViolation);
                        }
                        (
                            final_size - st.recv_fc.highest_received(),
                            st.recv_reset,
                            !has_send || st.fin_sent || st.send_stopped,
                        )
                    };
                    if !state.recv_fc.can_receive_delta(newly) {
                        return Err(MuxError::FlowControlViolation);
                    }
                    if already_reset {
                        return Ok(());
                    }
                    let ok_assoc = state.recv_fc.on_receive_delta(newly);
                    debug_assert!(ok_assoc);
                    {
                        let st = state.streams.get_mut(&stream_id).unwrap();
                        let ok_stream = st.recv_fc.on_receive_end(final_size);
                        debug_assert!(ok_stream);
                        let _ = st.rx.record_fin(final_size);
                        st.recv_reset = true;
                        st.rx.clear();
                    }
                    if can_retire {
                        state.retire_stream(stream_id, allow_slide);
                    } else {
                        let unconsumed = {
                            let st = state.streams.get_mut(&stream_id).unwrap();
                            let u = st
                                .recv_fc
                                .highest_received()
                                .saturating_sub(st.recv_fc.consumed());
                            if u > 0 {
                                st.recv_fc.on_consumed(u, false);
                            }
                            u
                        };
                        if unconsumed > 0 {
                            state.recv_fc.on_consumed(unconsumed, allow_slide);
                        }
                    }
                }
                cb.on_stream_closed(
                    assoc,
                    stream_id,
                    StreamCloseReason::PeerReset {
                        error_code,
                        final_size,
                    },
                );
            }
            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                let send_reset_final = {
                    let state = self
                        .associations
                        .get_mut(&assoc)
                        .ok_or(MuxError::UnknownAssociation)?;
                    if !state.has_local_send(stream_id) {
                        return Err(MuxError::InvalidStreamState);
                    }
                    if !state.ensure_stream_for_peer_frame(stream_id, None, init_stream_max)? {
                        return Ok(());
                    }
                    let has_recv = state.has_local_recv(stream_id);
                    let (already_stopped, need_rst, fsz, can_retire) = {
                        let st = state.streams.get_mut(&stream_id).unwrap();
                        let prev = st.send_stopped;
                        st.send_stopped = true;
                        let need_rst = !st.fin_sent;
                        let fsz = st.send_offset;
                        st.fin_sent = true;
                        let can_retire = !has_recv || st.recv_reset || st.rx.is_fin_delivered();
                        (prev, need_rst, fsz, can_retire)
                    };
                    if already_stopped {
                        return Ok(());
                    }
                    if can_retire {
                        state.retire_stream(stream_id, allow_slide);
                    }
                    need_rst.then_some(fsz)
                };
                egress.on_stream_aborted(assoc, stream_id);
                if let Some(final_size) = send_reset_final {
                    self.send_stream_abort_frames(
                        assoc,
                        stream_id,
                        final_size,
                        error_code,
                        true,
                        false,
                        egress,
                    );
                }
                cb.on_stream_closed(
                    assoc,
                    stream_id,
                    StreamCloseReason::PeerStopSending { error_code },
                );
            }
            Frame::ConnectionClose {
                is_application,
                error_code,
                frame_type,
            } => {
                if !self.associations.contains_key(&assoc) {
                    return Err(MuxError::UnknownAssociation);
                }
                cb.on_association_broken(
                    assoc,
                    AssociationBrokenReason::PeerConnectionClose {
                        is_application,
                        error_code,
                        frame_type,
                    },
                );
            }
            Frame::Padding | Frame::Ping | Frame::Stream(_) => {}
        }
        Ok(())
    }

    /// Validate flow control / FIN / duplicate trimming on incoming `STREAM` header, returning
    /// `Ok(None)` if already delivered, or `Ok(Some((trim_prefix, needs_queue, stream_prio)))`.
    fn prepare_stream_rx(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        offset: u64,
        len: usize,
        fin: bool,
    ) -> Result<Option<(usize, bool, StreamPriority)>, MuxError> {
        let end_offset = offset
            .checked_add(len as u64)
            .ok_or(MuxError::FlowControlViolation)?;
        let allow_slide = self.device_capacity > 0;
        let state = self
            .associations
            .get_mut(&assoc)
            .ok_or(MuxError::UnknownAssociation)?;
        if !state.has_local_recv(stream_id) {
            return Err(MuxError::InvalidStreamState);
        }
        let open = state.ensure_stream_for_peer_frame(
            stream_id,
            Some(end_offset),
            self.limits.initial_max_stream_data,
        )?;
        if !open {
            return Ok(None);
        }
        let newly_received = {
            let st = state.streams.get(&stream_id).unwrap();
            st.rx
                .check_bounds(end_offset, fin)
                .map_err(MuxError::Reassembly)?;
            if fin && end_offset < st.recv_fc.highest_received() {
                return Err(MuxError::Reassembly(ReassemblyError::FinalSizeConflict));
            }
            if !st.recv_fc.can_receive_end(end_offset) {
                return Err(MuxError::FlowControlViolation);
            }
            end_offset.saturating_sub(st.recv_fc.highest_received())
        };
        if !state.recv_fc.can_receive_delta(newly_received) {
            return Err(MuxError::FlowControlViolation);
        }
        let ok_assoc = state.recv_fc.on_receive_delta(newly_received);
        debug_assert!(ok_assoc);

        let is_reset = {
            let st = state.streams.get_mut(&stream_id).unwrap();
            let ok_stream = st.recv_fc.on_receive_end(end_offset);
            debug_assert!(ok_stream);
            if fin {
                st.rx.record_fin(end_offset).map_err(MuxError::Reassembly)?;
            }
            st.recv_reset
        };
        if is_reset {
            let unconsumed = {
                let st = state.streams.get_mut(&stream_id).unwrap();
                let u = st
                    .recv_fc
                    .highest_received()
                    .saturating_sub(st.recv_fc.consumed());
                if u > 0 {
                    st.recv_fc.on_consumed(u, false);
                }
                u
            };
            if unconsumed > 0 {
                state.recv_fc.on_consumed(unconsumed, allow_slide);
            }
            return Ok(None);
        }

        let st = state.streams.get(&stream_id).unwrap();
        let next_off = st.rx.next_offset();
        if end_offset < next_off
            || (end_offset == next_off && (!fin || st.rx.is_fin_delivered()))
        {
            return Ok(None);
        }
        let trim = if offset < next_off {
            (next_off - offset) as usize
        } else {
            0
        };
        let eff_offset = offset + trim as u64;
        Ok(Some((
            trim,
            st.rx.is_paused() || eff_offset > next_off,
            st.priority,
        )))
    }

    fn handle_stream_frame_owned(
        &mut self,
        meta: RxMeta,
        mut sf: StreamFrameRange,
        mut packet: P::Packet,
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) -> Result<(), MuxError> {
        let assoc = meta.association;
        let stream_id = sf.stream_id;
        let Some((trim, needs_queue, stream_prio)) =
            self.prepare_stream_rx(assoc, stream_id, sf.offset, sf.payload_range.len(), sf.fin)?
        else {
            return Ok(());
        };
        if trim > 0 {
            sf.payload_range.start += trim;
            sf.offset += trim as u64;
        }

        if needs_queue {
            if !self.ensure_rx_queue_capacity(assoc, stream_id, stream_prio, egress, cb) {
                self.abort_stream_under_pressure(assoc, stream_id, egress, cb);
                return Ok(());
            }
            let state = self
                .associations
                .get_mut(&assoc)
                .ok_or(MuxError::UnknownAssociation)?;
            if let Some(st) = state.streams.get_mut(&stream_id) {
                if let Err(ReassemblyError::QueueFull) = st.rx.insert_out_of_order(
                    sf.offset,
                    packet,
                    sf.payload_range,
                    sf.fin,
                    meta.received_at_us,
                ) {
                    self.abort_stream_under_pressure(assoc, stream_id, egress, cb);
                }
            }
            return Ok(());
        }

        // In-order fast path: pass exclusive ownership of `packet` (`refs == 1`) directly to handler!
        packet
            .set_range(sf.payload_range.clone())
            .map_err(MuxError::Pool)?;

        let outcome = cb.on_stream_data(
            assoc,
            stream_id,
            sf.offset,
            RxStreamChunk::from_packet(packet),
            sf.fin,
        );

        self.apply_delivery_outcome(
            assoc,
            stream_id,
            sf.offset,
            sf.payload_range,
            sf.fin,
            meta.received_at_us,
            egress,
            cb,
            outcome,
        )?;

        let _ = self.drain_in_order(assoc, stream_id, meta.received_at_us, egress, cb)?;
        Ok(())
    }

    fn handle_stream_frame_slice(
        &mut self,
        meta: RxMeta,
        mut sf: StreamFrameRange,
        mut slice: &[u8],
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) -> Result<(), MuxError> {
        let assoc = meta.association;
        let stream_id = sf.stream_id;
        let Some((trim, needs_queue, stream_prio)) =
            self.prepare_stream_rx(assoc, stream_id, sf.offset, slice.len(), sf.fin)?
        else {
            return Ok(());
        };
        if trim > 0 {
            slice = &slice[trim..];
            sf.offset += trim as u64;
        }

        if needs_queue {
            let needs_new_unit = self
                .associations
                .get(&assoc)
                .and_then(|a| a.streams.get(&stream_id))
                .is_none_or(|st| st.rx.would_increase_packet_units(slice.len()));
            if needs_new_unit
                && !self.ensure_rx_queue_capacity(assoc, stream_id, stream_prio, egress, cb)
            {
                self.abort_stream_under_pressure(assoc, stream_id, egress, cb);
                return Ok(());
            }
            let state = self
                .associations
                .get_mut(&assoc)
                .ok_or(MuxError::UnknownAssociation)?;
            if let Some(st) = state.streams.get_mut(&stream_id) {
                if let Err(ReassemblyError::QueueFull) = st.rx.insert_out_of_order_small(
                    sf.offset,
                    slice,
                    sf.fin,
                    meta.received_at_us,
                ) {
                    self.abort_stream_under_pressure(assoc, stream_id, egress, cb);
                }
            }
            return Ok(());
        }

        let outcome = cb.on_stream_data(
            assoc,
            stream_id,
            sf.offset,
            RxStreamChunk::from_slice(slice),
            sf.fin,
        );

        self.apply_delivery_outcome_slice(
            assoc,
            stream_id,
            sf.offset,
            slice,
            sf.fin,
            meta.received_at_us,
            egress,
            cb,
            outcome,
        )?;

        let _ = self.drain_in_order(assoc, stream_id, meta.received_at_us, egress, cb)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_delivery_outcome(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        offset: u64,
        payload_range: core::ops::Range<usize>,
        fin: bool,
        now_us: u64,
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
        outcome: Result<RxOutcome<P::Packet>, crate::flow::StreamError>,
    ) -> Result<usize, MuxError> {
        let payload_len = payload_range.len();
        let allow_slide = self.device_capacity > 0;
        let state = self
            .associations
            .get_mut(&assoc)
            .ok_or(MuxError::UnknownAssociation)?;
        let st = state
            .streams
            .get_mut(&stream_id)
            .ok_or(MuxError::UnknownStream)?;

        match outcome {
            Ok(RxOutcome::Consumed(n)) => {
                let consumed = n.min(payload_len);
                let fin_completed = fin && consumed == payload_len;
                st.rx.advance_delivered(consumed, fin_completed, now_us);
                st.recv_fc.on_consumed(consumed as u64, allow_slide);
                state.recv_fc.on_consumed(consumed as u64, allow_slide);
                Ok(consumed)
            }
            Ok(RxOutcome::Partial { consumed, packet }) => {
                let consumed = consumed.min(payload_len);
                let fin_completed = fin && consumed == payload_len;
                let prio = st.priority;
                st.rx.advance_delivered(consumed, fin_completed, now_us);
                st.recv_fc.on_consumed(consumed as u64, allow_slide);
                state.recv_fc.on_consumed(consumed as u64, allow_slide);

                if consumed < payload_len {
                    if !self.ensure_rx_queue_capacity(assoc, stream_id, prio, egress, cb) {
                        self.abort_stream_under_pressure(assoc, stream_id, egress, cb);
                        return Ok(consumed);
                    }
                    let rem_range = (payload_range.start + consumed)..payload_range.end;
                    if let Some(state) = self.associations.get_mut(&assoc) {
                        if let Some(st) = state.streams.get_mut(&stream_id) {
                            if st
                                .rx
                                .push_front_unconsumed(
                                    offset + consumed as u64,
                                    packet,
                                    rem_range,
                                    fin,
                                )
                                .is_err()
                            {
                                self.abort_stream_under_pressure(assoc, stream_id, egress, cb);
                            }
                        }
                    }
                }
                Ok(consumed)
            }
            Ok(RxOutcome::RetainedPendingCredit) => {
                st.rx.advance_delivered(payload_len, fin, now_us);
                Ok(payload_len)
            }
            Err(stream_err) => {
                let abort_info = {
                    let has_send = state.has_local_send(stream_id);
                    let has_recv = state.has_local_recv(stream_id);
                    state.retire_stream(stream_id, allow_slide).map(|st| {
                        (
                            st.send_offset,
                            has_send && !st.fin_sent,
                            has_recv && !st.recv_reset && !st.rx.is_fin_delivered(),
                        )
                    })
                };
                egress.on_stream_aborted(assoc, stream_id);
                if let Some((final_size, send_reset, send_stop)) = abort_info {
                    self.send_stream_abort_frames(
                        assoc,
                        stream_id,
                        final_size,
                        stream_err.error_code,
                        send_reset,
                        send_stop,
                        egress,
                    );
                }
                Ok(0)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_delivery_outcome_slice(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        offset: u64,
        slice: &[u8],
        fin: bool,
        now_us: u64,
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
        outcome: Result<RxOutcome<P::Packet>, crate::flow::StreamError>,
    ) -> Result<usize, MuxError> {
        let payload_len = slice.len();
        let allow_slide = self.device_capacity > 0;
        let state = self
            .associations
            .get_mut(&assoc)
            .ok_or(MuxError::UnknownAssociation)?;
        let st = state
            .streams
            .get_mut(&stream_id)
            .ok_or(MuxError::UnknownStream)?;

        match outcome {
            Ok(RxOutcome::Consumed(n)) | Ok(RxOutcome::Partial { consumed: n, .. }) => {
                let consumed = n.min(payload_len);
                let fin_completed = fin && consumed == payload_len;
                let prio = st.priority;
                st.rx.advance_delivered(consumed, fin_completed, now_us);
                st.recv_fc.on_consumed(consumed as u64, allow_slide);
                state.recv_fc.on_consumed(consumed as u64, allow_slide);

                if consumed < payload_len {
                    let rem = &slice[consumed..];
                    let needs_new_unit = st.rx.would_increase_packet_units(rem.len());
                    if needs_new_unit
                        && !self.ensure_rx_queue_capacity(assoc, stream_id, prio, egress, cb)
                    {
                        self.abort_stream_under_pressure(assoc, stream_id, egress, cb);
                        return Ok(consumed);
                    }
                    if let Some(state) = self.associations.get_mut(&assoc) {
                        if let Some(st) = state.streams.get_mut(&stream_id) {
                            if st
                                .rx
                                .push_front_unconsumed_small(offset + consumed as u64, rem, fin)
                                .is_err()
                            {
                                self.abort_stream_under_pressure(assoc, stream_id, egress, cb);
                            }
                        }
                    }
                }
                Ok(consumed)
            }
            Ok(RxOutcome::RetainedPendingCredit) => {
                st.rx.advance_delivered(payload_len, fin, now_us);
                Ok(payload_len)
            }
            Err(stream_err) => {
                let abort_info = {
                    let has_send = state.has_local_send(stream_id);
                    let has_recv = state.has_local_recv(stream_id);
                    state.retire_stream(stream_id, allow_slide).map(|st| {
                        (
                            st.send_offset,
                            has_send && !st.fin_sent,
                            has_recv && !st.recv_reset && !st.rx.is_fin_delivered(),
                        )
                    })
                };
                egress.on_stream_aborted(assoc, stream_id);
                if let Some((final_size, send_reset, send_stop)) = abort_info {
                    self.send_stream_abort_frames(
                        assoc,
                        stream_id,
                        final_size,
                        stream_err.error_code,
                        send_reset,
                        send_stop,
                        egress,
                    );
                }
                Ok(0)
            }
        }
    }

    fn drain_in_order(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        now_us: u64,
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) -> Result<usize, MuxError> {
        let mut total_delivered = 0usize;
        loop {
            let next_chunk = {
                let Some(state) = self.associations.get_mut(&assoc) else {
                    break;
                };
                let Some(st) = state.streams.get_mut(&stream_id) else {
                    break;
                };
                st.rx.pop_next_in_order(now_us)
            };
            let Some(chunk) = next_chunk else {
                break;
            };
            match chunk.payload {
                QueuedPayload::Packet(pkt) => {
                    let r = pkt.range();
                    let len = r.len();
                    let outcome = cb.on_stream_data(
                        assoc,
                        stream_id,
                        chunk.offset,
                        RxStreamChunk::from_packet(pkt),
                        chunk.fin,
                    );
                    let n = self.apply_delivery_outcome(
                        assoc,
                        stream_id,
                        chunk.offset,
                        r,
                        chunk.fin,
                        now_us,
                        egress,
                        cb,
                        outcome,
                    )?;
                    total_delivered += n;
                    if n < len {
                        break;
                    }
                }
                QueuedPayload::Small { data, range } => {
                    let slice = &data[range];
                    let len = slice.len();
                    let outcome = cb.on_stream_data(
                        assoc,
                        stream_id,
                        chunk.offset,
                        RxStreamChunk::from_slice(slice),
                        chunk.fin,
                    );
                    let n = self.apply_delivery_outcome_slice(
                        assoc,
                        stream_id,
                        chunk.offset,
                        slice,
                        chunk.fin,
                        now_us,
                        egress,
                        cb,
                        outcome,
                    )?;
                    total_delivered += n;
                    if n < len {
                        break;
                    }
                }
            }
        }
        Ok(total_delivered)
    }

    /// Ensure there is room for 1 additional RX packet on `(assoc, stream_id)` with `stream_prio`.
    ///
    /// Evicts strictly lower-priority streams (`victim.priority > stream_prio`) if needed to stay
    /// within the association and device RX packet limits. Returns `false` if `(assoc, stream_id)`
    /// itself must be reset/terminated.
    fn ensure_rx_queue_capacity(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        stream_prio: StreamPriority,
        egress: &mut impl AssociationEgress<P::Packet>,
        cb: &mut impl MuxCallbacks<P::Packet>,
    ) -> bool {
        let assoc_limit = {
            let Some(state) = self.associations.get(&assoc) else {
                return false;
            };
            let Some(st) = state.streams.get(&stream_id) else {
                return false;
            };
            if st.rx.queued_chunks() >= st.rx.max_chunks() {
                return false;
            }
            state.limits.max_rx_queued_packets
        };

        if assoc_limit == 0 || self.device_max_rx_packets == 0 {
            return false;
        }

        while self.association_rx_queued_packets(assoc).unwrap_or(0) >= assoc_limit {
            let Some(victim_stream) = self.select_assoc_victim_stream(assoc, Some(stream_prio))
            else {
                return false;
            };
            if !self.abort_stream_under_pressure(assoc, victim_stream, egress, cb) {
                return false;
            }
        }

        while self.total_rx_queued_packets() >= self.device_max_rx_packets {
            let Some((victim_assoc, victim_stream)) =
                self.select_device_victim_stream(Some(stream_prio))
            else {
                return false;
            };
            if !self.abort_stream_under_pressure(victim_assoc, victim_stream, egress, cb) {
                return false;
            }
        }

        true
    }

    fn select_assoc_victim_stream(
        &self,
        assoc: AssociationId,
        must_be_lower_than: Option<StreamPriority>,
    ) -> Option<StreamId> {
        let state = self.associations.get(&assoc)?;
        let mut best: Option<(u8, usize, StreamId)> = None;
        for (&sid, st) in &state.streams {
            let q = st.rx.queued_chunks();
            if q == 0 {
                continue;
            }
            if let Some(req) = must_be_lower_than {
                if !st.priority.is_lower_than(req) {
                    continue;
                }
            }
            let key = (st.priority.0, q, sid);
            if best.is_none_or(|b| (key.0, key.1) > (b.0, b.1)) {
                best = Some(key);
            }
        }
        best.map(|(_, _, sid)| sid)
    }

    fn select_device_victim_stream(
        &self,
        must_be_lower_than: Option<StreamPriority>,
    ) -> Option<(AssociationId, StreamId)> {
        let mut best: Option<(u8, usize, AssociationId, StreamId)> = None;
        for (&aid, state) in &self.associations {
            for (&sid, st) in &state.streams {
                let q = st.rx.queued_chunks();
                if q == 0 {
                    continue;
                }
                if let Some(req) = must_be_lower_than {
                    if !st.priority.is_lower_than(req) {
                        continue;
                    }
                }
                let key = (st.priority.0, q, aid, sid);
                if best.is_none_or(|b| (key.0, key.1) > (b.0, b.1)) {
                    best = Some(key);
                }
            }
        }
        best.map(|(_, _, aid, sid)| (aid, sid))
    }

    #[allow(clippy::too_many_arguments)]
    fn send_stream_abort_frames(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        final_size: u64,
        error_code: u64,
        send_reset: bool,
        send_stop: bool,
        egress: &mut impl AssociationEgress<P::Packet>,
    ) {
        if !send_reset && !send_stop {
            return;
        }
        if egress.max_writable_frame_len(assoc) < 32 {
            return;
        }
        let Ok(mut pkt) = self.pool.alloc() else {
            return;
        };
        let mut buf = [0u8; 48];
        let mut at = 0usize;
        if send_reset {
            if let Ok(n) = encode_control_frame(
                &Frame::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                },
                &mut buf[at..],
            ) {
                at += n;
            }
        }
        if send_stop {
            if let Ok(n) = encode_control_frame(
                &Frame::StopSending {
                    stream_id,
                    error_code,
                },
                &mut buf[at..],
            ) {
                at += n;
            }
        }
        if at > 0 && pkt.append(&buf[..at]).is_ok() {
            let _ = egress.send_packet(
                TxPacketMeta {
                    association: assoc,
                    stream_id: Some(stream_id),
                    priority: StreamPriority::CRITICAL,
                    retransmittable: true,
                },
                pkt,
            );
        }
    }
}
