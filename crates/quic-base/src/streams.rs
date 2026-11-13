//! Per-stream state, zero-copy `PoolPacket` ordered reassembly, and gap timeout tracking.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::ops::Range;

use crate::flow::{RecvFlowControl, SendFlowControl, StreamPriority};
use crate::pool::{DEFAULT_MAX_PAYLOAD, PoolError, PoolPacket};
use crate::wire::StreamId;

pub use mesh_api::stream::{RxStreamChunk, TxStreamData};

/// Backing storage for an out-of-order or partially-consumed RX stream chunk.
pub enum QueuedPayload<P: PoolPacket> {
    /// Owned `PoolPacket` lease (single-stream packet or `> 1/2 MTU` frame in a multi-frame packet).
    Packet(P),
    /// Compact heap buffer for a small (`<= 1/2 MTU`) frame extracted from a multi-frame packet
    /// so it does not pin a full MTU pool slot.
    Small {
        /// Owned small payload bytes.
        data: Box<[u8]>,
        /// Active unconsumed sub-slice within `data`.
        range: Range<usize>,
    },
}

impl<P: PoolPacket> QueuedPayload<P> {
    /// Active payload slice.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Packet(pkt) => pkt.bytes(),
            Self::Small { data, range } => &data[range.clone()],
        }
    }

    /// Length of the active payload slice in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes().len()
    }

    /// Whether the active payload slice is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn trim_prefix(&mut self, trim: usize) {
        match self {
            Self::Packet(pkt) => {
                let r = pkt.range();
                let _ = pkt.set_range(r.start + trim..r.end);
            }
            Self::Small { range, .. } => {
                range.start += trim;
            }
        }
    }
}

/// One retained out-of-order or partially-consumed stream chunk.
pub struct QueuedChunk<P: PoolPacket> {
    /// Stream byte offset corresponding to the start of `payload`.
    pub offset: u64,
    /// Backing payload (`PoolPacket` or compact small buffer).
    pub payload: QueuedPayload<P>,
    /// Whether this chunk carries the stream's `FIN`.
    pub fin: bool,
}

/// Zero-copy per-stream ordered reassembly queue and gap-timeout tracker.
pub struct OrderedStream<P: PoolPacket> {
    next_deliver_offset: u64,
    final_size: Option<u64>,
    fin_delivered: bool,
    paused_by_consumer: bool,
    gap_started_at_us: Option<u64>,
    max_chunks: usize,
    queue: VecDeque<QueuedChunk<P>>,
}

/// Errors during ordered stream reassembly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReassemblyError {
    /// Reassembly queue reached its fixed-capacity chunk limit.
    QueueFull,
    /// `FIN` offset conflicts with previously observed stream data.
    FinalSizeConflict,
    /// Pool could not retain a packet reference.
    Pool(PoolError),
}

impl<P: PoolPacket> OrderedStream<P> {
    /// Create a new ordered reassembly state with fixed-capacity `max_chunks`.
    pub fn new(max_chunks: usize) -> Self {
        Self {
            next_deliver_offset: 0,
            final_size: None,
            fin_delivered: false,
            paused_by_consumer: false,
            gap_started_at_us: None,
            max_chunks,
            queue: VecDeque::new(),
        }
    }

    /// Next contiguous stream offset expected for in-order delivery.
    #[inline]
    pub const fn next_offset(&self) -> u64 {
        self.next_deliver_offset
    }

    /// Whether the stream has delivered all bytes up to `FIN`.
    #[inline]
    pub const fn is_fin_delivered(&self) -> bool {
        self.fin_delivered
    }

    /// Whether the consumer returned a partial count (`Consumed(n) < len`) and paused delivery.
    #[inline]
    pub const fn is_paused(&self) -> bool {
        self.paused_by_consumer
    }

    /// Clear consumer pause flag (called by `resume_stream`).
    #[inline]
    pub fn clear_pause(&mut self) {
        self.paused_by_consumer = false;
    }

    /// Number of MTU-equivalent packet units currently held (`PoolPacket` count plus
    /// `ceil(small_bytes / DEFAULT_MAX_PAYLOAD)`).
    pub fn queued_chunks(&self) -> usize {
        let mut pkt_units = 0usize;
        let mut small_bytes = 0usize;
        for c in &self.queue {
            match &c.payload {
                QueuedPayload::Packet(_) => pkt_units += 1,
                QueuedPayload::Small { range, .. } => small_bytes += range.len(),
            }
        }
        pkt_units + small_bytes.div_ceil(DEFAULT_MAX_PAYLOAD)
    }

    /// Whether appending `additional_small_bytes` to `Small` buffers would increase [`Self::queued_chunks`].
    pub fn would_increase_packet_units(&self, additional_small_bytes: usize) -> bool {
        let mut small_bytes = 0usize;
        for c in &self.queue {
            if let QueuedPayload::Small { range, .. } = &c.payload {
                small_bytes += range.len();
            }
        }
        let before = small_bytes.div_ceil(DEFAULT_MAX_PAYLOAD);
        let after = small_bytes
            .saturating_add(additional_small_bytes.max(1))
            .div_ceil(DEFAULT_MAX_PAYLOAD);
        after > before
    }

    /// Current dynamic limit on queued chunks for this stream.
    #[inline]
    pub const fn max_chunks(&self) -> usize {
        self.max_chunks
    }

    /// Update the dynamic limit on queued chunks for this stream.
    #[inline]
    pub fn set_max_chunks(&mut self, max_chunks: usize) {
        self.max_chunks = max_chunks;
    }

    /// Timestamp when the current missing-frame gap started (`Some` only when `queue` holds
    /// out-of-order chunks with `offset > next_deliver_offset`).
    #[inline]
    pub const fn gap_started_at_us(&self) -> Option<u64> {
        self.gap_started_at_us
    }

    /// Deadline (`gap_started_at_us + gap_timeout_us`) at which a missing middle frame times out.
    #[inline]
    pub fn gap_deadline_us(&self, gap_timeout_us: u64) -> Option<u64> {
        self.gap_started_at_us
            .map(|start| start.saturating_add(gap_timeout_us))
    }

    /// Recorded `FIN` / `RESET_STREAM` final byte size of the stream, if known.
    #[inline]
    pub const fn final_size(&self) -> Option<u64> {
        self.final_size
    }

    /// Validate that `end_offset` is consistent with any previously recorded `FIN` / `final_size`
    /// (and, if `is_fin` is true, not smaller than `next_deliver_offset`), without mutating state.
    pub fn check_bounds(&self, end_offset: u64, is_fin: bool) -> Result<(), ReassemblyError> {
        if let Some(existing) = self.final_size {
            if is_fin {
                if end_offset != existing {
                    return Err(ReassemblyError::FinalSizeConflict);
                }
            } else if end_offset > existing {
                return Err(ReassemblyError::FinalSizeConflict);
            }
        }
        Ok(())
    }

    /// Check and record `FIN` final size consistency.
    pub fn record_fin(&mut self, end_offset: u64) -> Result<(), ReassemblyError> {
        self.check_bounds(end_offset, true)?;
        self.final_size = Some(end_offset);
        Ok(())
    }

    /// Advance `next_deliver_offset` after in-order consumption.
    pub fn advance_delivered(&mut self, consumed: usize, fin_completed: bool, now_us: u64) {
        self.next_deliver_offset = self.next_deliver_offset.saturating_add(consumed as u64);
        if fin_completed {
            self.fin_delivered = true;
        }
        self.refresh_gap_timer(now_us);
    }

    /// Push an unconsumed suffix of an in-order packet to the front of the queue and pause delivery.
    pub fn push_front_unconsumed(
        &mut self,
        offset: u64,
        mut packet: P,
        unconsumed_range: Range<usize>,
        fin: bool,
    ) -> Result<(), ReassemblyError> {
        if self.queued_chunks() >= self.max_chunks {
            return Err(ReassemblyError::QueueFull);
        }
        packet
            .set_range(unconsumed_range)
            .map_err(ReassemblyError::Pool)?;
        self.queue.push_front(QueuedChunk {
            offset,
            payload: QueuedPayload::Packet(packet),
            fin,
        });
        self.paused_by_consumer = true;
        // Not a network gap: offset == next_deliver_offset, held only for consumer backpressure.
        self.gap_started_at_us = None;
        Ok(())
    }

    /// Push an unconsumed suffix of a small (`<= 1/2 MTU`) slice to the front of the queue and pause delivery.
    pub fn push_front_unconsumed_small(
        &mut self,
        offset: u64,
        unconsumed_bytes: &[u8],
        fin: bool,
    ) -> Result<(), ReassemblyError> {
        if self.would_increase_packet_units(unconsumed_bytes.len())
            && self.queued_chunks() >= self.max_chunks
        {
            return Err(ReassemblyError::QueueFull);
        }
        let len = unconsumed_bytes.len();
        self.queue.push_front(QueuedChunk {
            offset,
            payload: QueuedPayload::Small {
                data: Box::from(unconsumed_bytes),
                range: 0..len,
            },
            fin,
        });
        self.paused_by_consumer = true;
        self.gap_started_at_us = None;
        Ok(())
    }

    /// Insert an out-of-order (or paused) `PoolPacket` chunk into `queue` sorted by `offset`,
    /// deduplicating overlapping ranges in-place.
    pub fn insert_out_of_order(
        &mut self,
        mut offset: u64,
        mut packet: P,
        mut payload_range: Range<usize>,
        fin: bool,
        now_us: u64,
    ) -> Result<(), ReassemblyError> {
        let len = payload_range.len() as u64;
        let end = offset.saturating_add(len);
        if fin {
            self.record_fin(end)?;
        }
        if end <= self.next_deliver_offset && !(fin && end == self.next_deliver_offset) {
            return Ok(());
        }
        if offset < self.next_deliver_offset {
            let trim = (self.next_deliver_offset - offset) as usize;
            payload_range.start += trim;
            offset = self.next_deliver_offset;
        }

        // Check for exact duplicate in queue
        if self
            .queue
            .iter()
            .any(|c| c.offset == offset && c.payload.len() >= payload_range.len())
        {
            return Ok(());
        }

        if self.queued_chunks() >= self.max_chunks {
            return Err(ReassemblyError::QueueFull);
        }

        packet
            .set_range(payload_range)
            .map_err(ReassemblyError::Pool)?;

        let pos = self
            .queue
            .iter()
            .position(|c| c.offset > offset)
            .unwrap_or(self.queue.len());
        self.queue.insert(
            pos,
            QueuedChunk {
                offset,
                payload: QueuedPayload::Packet(packet),
                fin,
            },
        );
        self.refresh_gap_timer(now_us);
        Ok(())
    }

    /// Insert an out-of-order (or paused) small (`<= 1/2 MTU`) payload slice into `queue` sorted by `offset`.
    pub fn insert_out_of_order_small(
        &mut self,
        mut offset: u64,
        mut bytes: &[u8],
        fin: bool,
        now_us: u64,
    ) -> Result<(), ReassemblyError> {
        let len = bytes.len() as u64;
        let end = offset.saturating_add(len);
        if fin {
            self.record_fin(end)?;
        }
        if end <= self.next_deliver_offset && !(fin && end == self.next_deliver_offset) {
            return Ok(());
        }
        if offset < self.next_deliver_offset {
            let trim = (self.next_deliver_offset - offset) as usize;
            bytes = &bytes[trim..];
            offset = self.next_deliver_offset;
        }

        if self
            .queue
            .iter()
            .any(|c| c.offset == offset && c.payload.len() >= bytes.len())
        {
            return Ok(());
        }

        if self.would_increase_packet_units(bytes.len()) && self.queued_chunks() >= self.max_chunks
        {
            return Err(ReassemblyError::QueueFull);
        }

        let slice_len = bytes.len();
        let pos = self
            .queue
            .iter()
            .position(|c| c.offset > offset)
            .unwrap_or(self.queue.len());
        self.queue.insert(
            pos,
            QueuedChunk {
                offset,
                payload: QueuedPayload::Small {
                    data: Box::from(bytes),
                    range: 0..slice_len,
                },
                fin,
            },
        );
        self.refresh_gap_timer(now_us);
        Ok(())
    }

    /// Pop the next contiguous chunk if its `offset <= next_deliver_offset`.
    /// Trims any overlapping prefix if an earlier chunk partially covered it.
    pub fn pop_next_in_order(&mut self, now_us: u64) -> Option<QueuedChunk<P>> {
        if self.paused_by_consumer {
            return None;
        }
        while let Some(front) = self.queue.front() {
            if front.offset > self.next_deliver_offset {
                break;
            }
            let mut chunk = self.queue.pop_front()?;
            let chunk_len = chunk.payload.len() as u64;
            let chunk_end = chunk.offset.saturating_add(chunk_len);
            if chunk_end < self.next_deliver_offset
                || (chunk_end == self.next_deliver_offset && !chunk.fin)
            {
                // Already delivered by an earlier overlapping frame; drop lease and continue.
                continue;
            }
            if chunk.offset < self.next_deliver_offset {
                let trim = (self.next_deliver_offset - chunk.offset) as usize;
                chunk.payload.trim_prefix(trim);
                chunk.offset = self.next_deliver_offset;
            }
            self.refresh_gap_timer(now_us);
            return Some(chunk);
        }
        self.refresh_gap_timer(now_us);
        None
    }

    /// Clear all queued `PoolPacket` leases (releasing them back to the pool).
    pub fn clear(&mut self) {
        self.queue.clear();
        self.gap_started_at_us = None;
    }

    fn refresh_gap_timer(&mut self, now_us: u64) {
        match self.queue.front() {
            Some(front) if front.offset > self.next_deliver_offset => {
                if self.gap_started_at_us.is_none() {
                    self.gap_started_at_us = Some(now_us);
                }
            }
            _ => {
                self.gap_started_at_us = None;
            }
        }
    }
}

/// Complete per-stream state inside an association.
pub struct StreamState<P: PoolPacket> {
    /// Stream identifier.
    pub id: StreamId,
    /// Stream priority (`0` = highest/critical, `255` = lowest/bulk).
    pub priority: StreamPriority,
    /// Receive-side flow control (`MAX_STREAM_DATA`).
    pub recv_fc: RecvFlowControl,
    /// Send-side flow control (`MAX_STREAM_DATA`).
    pub send_fc: SendFlowControl,
    /// Next byte offset to send on this stream.
    pub send_offset: u64,
    /// Whether `FIN` has been sent on this stream.
    pub fin_sent: bool,
    /// Whether the send half is stopped (either because the peer sent `STOP_SENDING`, or because
    /// this stream has no local send half, e.g. peer-initiated unidirectional stream).
    pub send_stopped: bool,
    /// Whether the receive half is closed/reset (either because the peer sent `RESET_STREAM` or
    /// because this stream has no local receive half, e.g. locally-initiated unidirectional stream).
    pub recv_reset: bool,
    /// Ordered reassembly queue and gap-timeout tracker.
    pub rx: OrderedStream<P>,
}

impl<P: PoolPacket> StreamState<P> {
    /// Create a new stream state with initial flow-control windows, priority, and chunk queue limit.
    pub fn new(
        id: StreamId,
        priority: StreamPriority,
        initial_recv_max: u64,
        initial_send_max: u64,
        max_queued_chunks: usize,
    ) -> Self {
        Self {
            id,
            priority,
            recv_fc: RecvFlowControl::new(initial_recv_max),
            send_fc: SendFlowControl::new(initial_send_max),
            send_offset: 0,
            fin_sent: false,
            send_stopped: false,
            recv_reset: false,
            rx: OrderedStream::new(max_queued_chunks),
        }
    }
}
