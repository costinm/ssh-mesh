//! Three-level flow control and application callback definitions.

use crate::link::AssociationId;
use crate::pool::PoolPacket;
use crate::streams::RxStreamChunk;
use crate::wire::StreamId;

/// Application error code sent in `RESET_STREAM` / `STOP_SENDING` when a stream is
/// terminated due to RX/TX packet pool pressure.
pub const RESOURCE_PRESSURE_ERROR_CODE: u64 = 0x5155_4943_0001;

/// Application error code sent in `RESET_STREAM` / `STOP_SENDING` when a stream is
/// terminated because an out-of-order middle-frame gap exceeded `gap_timeout_us`.
pub const GAP_TIMEOUT_ERROR_CODE: u64 = 0x5155_4943_0002;

/// Stream priority level (`0` = highest/critical priority, `255` = lowest/bulk priority).
///
/// Under RX out-of-order or TX retransmit memory pressure, streams with lower importance
/// (larger numeric value) are evicted and reset (`RST`) first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamPriority(pub u8);

impl StreamPriority {
    /// Highest priority (control, keepalive, urgent signaling).
    pub const CRITICAL: Self = Self(0);
    /// High priority (interactive RPC / shell).
    pub const HIGH: Self = Self(64);
    /// Default normal priority.
    pub const NORMAL: Self = Self(128);
    /// Low priority.
    pub const LOW: Self = Self(192);
    /// Lowest priority (background bulk transfer, evicted first under load).
    pub const BULK: Self = Self(255);

    /// True if `self` is strictly higher importance than `other` (`self.0 < other.0`).
    #[inline]
    pub const fn is_higher_than(self, other: Self) -> bool {
        self.0 < other.0
    }

    /// True if `self` is strictly lower importance than `other` (`self.0 > other.0`).
    #[inline]
    pub const fn is_lower_than(self, other: Self) -> bool {
        self.0 > other.0
    }
}

impl Default for StreamPriority {
    fn default() -> Self {
        Self::NORMAL
    }
}

/// Receive-side flow control tracker (used for both association `MAX_DATA` and stream `MAX_STREAM_DATA`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvFlowControl {
    window_size: u64,
    max_data_advertised: u64,
    highest_received: u64,
    consumed_bytes: u64,
    update_pending: bool,
}

impl RecvFlowControl {
    /// Create a receive flow-control state with initial window `window_size`.
    pub const fn new(window_size: u64) -> Self {
        Self {
            window_size,
            max_data_advertised: window_size,
            highest_received: 0,
            consumed_bytes: 0,
            update_pending: false,
        }
    }

    /// Maximum offset currently advertised to the peer.
    #[inline]
    pub const fn advertised_max(&self) -> u64 {
        self.max_data_advertised
    }

    /// Highest byte offset received so far.
    #[inline]
    pub const fn highest_received(&self) -> u64 {
        self.highest_received
    }

    /// Total bytes consumed by the application so far.
    #[inline]
    pub const fn consumed(&self) -> u64 {
        self.consumed_bytes
    }

    /// Check whether `end_offset` is within the advertised window without mutating state.
    #[inline]
    pub const fn can_receive_end(&self, end_offset: u64) -> bool {
        end_offset <= self.max_data_advertised
    }

    /// Check whether `delta` newly received bytes fit within the advertised window without mutating state.
    #[inline]
    pub const fn can_receive_delta(&self, delta: u64) -> bool {
        match self.highest_received.checked_add(delta) {
            Some(new_total) => new_total <= self.max_data_advertised,
            None => false,
        }
    }

    /// Validate and record receipt of bytes up to `end_offset` (or `delta` for connection-level).
    pub fn on_receive_end(&mut self, end_offset: u64) -> bool {
        if end_offset > self.max_data_advertised {
            return false;
        }
        if end_offset > self.highest_received {
            self.highest_received = end_offset;
        }
        true
    }

    /// Record `delta` newly received bytes (for connection-level `MAX_DATA`).
    pub fn on_receive_delta(&mut self, delta: u64) -> bool {
        let Some(new_total) = self.highest_received.checked_add(delta) else {
            return false;
        };
        self.on_receive_end(new_total)
    }

    /// Record that the application consumed `count` bytes.
    ///
    /// Marks a window update pending when remaining advertised credit falls below half of `window_size`.
    pub fn on_consumed(&mut self, count: u64, allow_window_slide: bool) {
        self.consumed_bytes = self.consumed_bytes.saturating_add(count);
        if allow_window_slide {
            let new_limit = self.consumed_bytes.saturating_add(self.window_size);
            if new_limit.saturating_sub(self.max_data_advertised) >= (self.window_size / 2).max(1) {
                self.max_data_advertised = new_limit;
                self.update_pending = true;
            }
        }
    }

    /// Whether a `MAX_DATA` or `MAX_STREAM_DATA` frame needs to be sent to the peer.
    #[inline]
    pub const fn has_pending_update(&self) -> bool {
        self.update_pending
    }

    /// Peek the pending `MAX_DATA` / `MAX_STREAM_DATA` value without clearing the pending flag.
    #[inline]
    pub const fn peek_pending_update(&self) -> Option<u64> {
        if self.update_pending {
            Some(self.max_data_advertised)
        } else {
            None
        }
    }

    /// Clear the pending update flag once the packet carrying the update has been accepted by a link.
    #[inline]
    pub fn clear_pending_update(&mut self) {
        self.update_pending = false;
    }
}

/// Send-side flow control tracker (tracks `sent_bytes` against peer's advertised `max_data`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendFlowControl {
    max_data_peer: u64,
    sent_bytes: u64,
}

impl SendFlowControl {
    /// Create a send flow-control tracker with initial peer limit `initial_max_data`.
    pub const fn new(initial_max_data: u64) -> Self {
        Self {
            max_data_peer: initial_max_data,
            sent_bytes: 0,
        }
    }

    /// Remaining bytes that may be sent within the peer's advertised window.
    #[inline]
    pub const fn available(&self) -> u64 {
        self.max_data_peer.saturating_sub(self.sent_bytes)
    }

    /// Total bytes sent so far.
    #[inline]
    pub const fn sent(&self) -> u64 {
        self.sent_bytes
    }

    /// Peer's advertised limit.
    #[inline]
    pub const fn peer_max(&self) -> u64 {
        self.max_data_peer
    }

    /// Commit `count` sent bytes after a link accepts a packet.
    #[inline]
    pub fn commit_send(&mut self, count: u64) {
        self.sent_bytes = self.sent_bytes.saturating_add(count);
    }

    /// Apply a `MAX_DATA` or `MAX_STREAM_DATA` update from the peer.
    /// Returns `true` if the available window increased.
    #[inline]
    pub fn update_peer_max(&mut self, new_max: u64) -> bool {
        if new_max > self.max_data_peer {
            self.max_data_peer = new_max;
            true
        } else {
            false
        }
    }
}

/// Snapshot of a stream's current send capacity across all 3 flow-control tiers and link MTU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamSendCapacity {
    /// Exact maximum payload bytes the caller can place in a single packet right now:
    /// `min(device_capacity, assoc_window, stream_window, link_max_payload)`.
    pub max_chunk_bytes: usize,
    /// Remaining bytes allowed by the peer's `MAX_STREAM_DATA` on this stream.
    pub stream_window: u64,
    /// Remaining bytes allowed by the peer's `MAX_DATA` on this association.
    pub association_window: u64,
    /// True if global device capacity > 0 and the association has a ready link.
    pub can_send_now: bool,
}

pub use mesh_api::stream::RxOutcome;

/// Error returned by a stream handler when rejecting incoming data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamError {
    /// Application error code to report in `STOP_SENDING` / `RESET_STREAM`.
    pub error_code: u64,
}

/// Reason a stream was closed or aborted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamCloseReason {
    /// Peer sent `RESET_STREAM(error_code, final_size)`.
    PeerReset {
        /// Peer error code.
        error_code: u64,
        /// Final byte size reported by peer.
        final_size: u64,
    },
    /// Peer sent `STOP_SENDING(error_code)`.
    PeerStopSending {
        /// Peer error code.
        error_code: u64,
    },
    /// A missing middle frame was not received before `gap_timeout_us` expired (broken stream / RST).
    GapTimeout {
        /// First missing stream offset that timed out.
        missing_offset: u64,
    },
    /// Stream was reset/terminated because RX out-of-order or TX retransmit packet retention
    /// exceeded dynamic device, association, or stream limits under load.
    ResourcePressure {
        /// Contiguous byte offset delivered before termination.
        delivered_offset: u64,
    },
    /// Association was closed or removed before this stream completed.
    AssociationClosed {
        /// Contiguous byte offset delivered before close.
        delivered_offset: u64,
    },
}

/// Reason `quic-mux` determined that an association is broken and should reconnect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssociationBrokenReason {
    /// A stream had an out-of-order gap at `missing_offset` that timed out after `gap_timeout_us`.
    StreamGapTimeout {
        /// Affected stream identifier.
        stream_id: StreamId,
        /// Missing byte offset that never arrived.
        missing_offset: u64,
    },
    /// Peer sent `CONNECTION_CLOSE` (`0x1c` transport or `0x1d` application).
    PeerConnectionClose {
        /// `true` for application close (`0x1d`), `false` for transport close (`0x1c`).
        is_application: bool,
        /// Error code sent by the peer.
        error_code: u64,
        /// Triggering frame type (`0` for application close `0x1d`).
        frame_type: u64,
    },
}

/// Application and association event callbacks invoked by [` crate::mux::QuicMux `].
pub trait MuxCallbacks<P: PoolPacket> {
    /// Deliver in-order stream data.
    ///
    /// - Single-stream packet: `chunk.packet` is `Some(P)` (ownership passed directly to handler).
    /// - Multi-stream packet or borrowed suffix: `chunk.packet` is `None` and `chunk.small_buf` is populated.
    fn on_stream_data(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        offset: u64,
        chunk: RxStreamChunk<'_, P>,
        fin: bool,
    ) -> Result<RxOutcome<P>, StreamError>;

    /// Stream was reset by peer (`RESET_STREAM`), aborted by missing-frame timeout (`GapTimeout`),
    /// or closed when the association ended.
    fn on_stream_closed(
        &mut self,
        _assoc: AssociationId,
        _stream_id: StreamId,
        _reason: StreamCloseReason,
    ) {
    }

    /// Notifies the association layer that the connection appears broken (e.g., an out-of-order
    /// stream gap timed out without receiving the missing middle frame) and should reconnect.
    fn on_association_broken(&mut self, _assoc: AssociationId, _reason: AssociationBrokenReason) {}

    /// Peer sent `MAX_STREAM_DATA`, expanding this stream's send window.
    fn on_stream_writable(
        &mut self,
        _assoc: AssociationId,
        _stream_id: StreamId,
        _writable_bytes: usize,
    ) {
    }

    /// Peer sent `MAX_DATA` / `MAX_STREAMS`, or `on_association_ready` unlocked sending.
    fn on_association_writable(&mut self, _assoc: AssociationId, _association_window: u64) {}

    /// Global device capacity recovered from overload.
    fn on_device_writable(&mut self) {}
}
