//! Association and link-layer egress abstraction, SACK tracking, and TX retransmit retention.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ops::Range;

use crate::flow::StreamPriority;
use crate::pool::PoolPacket;
use crate::wire::StreamId;

/// Opaque association identifier managed by the link/association layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssociationId(pub u32);

/// Fixed association ID (`1`) for the owner/master association shared across PPP/UART and TCP streams.
pub const OWNER_ASSOC: AssociationId = AssociationId(1);

/// Alias for [`OWNER_ASSOC`] (`AssociationId(1)`).
pub const MASTER_ASSOC: AssociationId = OWNER_ASSOC;

/// Metadata passed with an inbound packet from the association/link layer to `quic-mux`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxMeta {
    /// Association that received the packet.
    pub association: AssociationId,
    /// Monotonic receive timestamp in microseconds.
    pub received_at_us: u64,
}

/// Metadata passed with an outbound `PoolPacket` when `quic-mux` hands ownership of a TX buffer
/// to the association/link layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxPacketMeta {
    /// Target association identifier.
    pub association: AssociationId,
    /// Primary stream carried by this packet (`None` for standalone control frames).
    pub stream_id: Option<StreamId>,
    /// Priority of the packet (`StreamPriority::CRITICAL` for control frames, or the stream's priority).
    pub priority: StreamPriority,
    /// Whether the association layer should retain this packet for Selective ACK / retransmission.
    pub retransmittable: bool,
}

/// Errors returned when offering a packet to an association's links.
#[derive(Debug, PartialEq, Eq)]
pub enum LinkSendError<P> {
    /// All candidate links (or the association's retransmit/congestion window) refused the packet (`Busy`).
    /// The exact packet `P` is returned so the caller retains ownership with no queue.
    Busy(P),
    /// Packet length exceeds the association's maximum writable frame size.
    TooLarge {
        /// Returned packet lease.
        packet: P,
        /// Current maximum frame length in bytes.
        max_frame_len: usize,
    },
    /// Association is unknown or has no usable links.
    NoAssociation(P),
}

/// Implemented by the association/connection layer below `quic-mux`.
///
/// `quic-mux` passes ownership of TX `PoolPacket` buffers to [`Self::send_packet`] along with
/// [`TxPacketMeta`]. The association/link layer:
/// 1. Selects the actual outgoing link (e.g. in cost order across TCP, UART, UDP, LoRa).
/// 2. **Small-packet coalescing (`<= 1/3 MTU`):** Every `quic-mux` `STREAM` frame carries an explicit
///    `LEN` varint (`0x02` bit) and every control frame is self-delimiting. Whenever a link already
///    has pending TX packets waiting to be transmitted, the link layer is explicitly allowed to
///    combine small outgoing packets (e.g. `<= mtu / 3`, see [`try_coalesce_tx_packet`]) onto the
///    tail of a pending packet for the same association (up to `mtu`), immediately releasing the
///    absorbed `PoolPacket` slot back to the pool.
/// 3. Retains a reference to `packet` in its Selective ACK / retransmit ledger if needed.
/// 4. Prepends connection/link headers in front of `packet.range().start` in-place.
pub trait AssociationEgress<P: PoolPacket> {
    /// Maximum frame bytes (including `quic-mux` headers) that `assoc` can currently accept
    /// on its best ready link. Returns `0` if all links for `assoc` are busy or down.
    fn max_writable_frame_len(&self, assoc: AssociationId) -> usize;

    /// Pass ownership of a framed `quic-mux` TX packet to the association/link layer.
    ///
    /// - The association layer selects the actual link, optionally coalesces small packets
    ///   (`<= mtu / 3`) into an already-pending packet for the same association via
    ///   [`try_coalesce_tx_packet`], and (if `meta.retransmittable`) retains the packet for
    ///   Selective ACK / retransmission.
    /// - If refused (`Busy`), returns `Err(LinkSendError::Busy(packet))` with no queue.
    fn send_packet(&mut self, meta: TxPacketMeta, packet: P) -> Result<(), LinkSendError<P>>;

    /// Notifies the association/link layer that `(assoc, stream_id)` was reset or terminated
    /// (e.g. due to RX/TX resource pressure or gap timeout) so any unACKed TX packets retained
    /// for that stream can be dropped immediately.
    fn on_stream_aborted(&mut self, _assoc: AssociationId, _stream_id: StreamId) {}
}

/// Default maximum packet length (`mtu / 3`) eligible for link-layer TX coalescing while a link
/// has pending packets.
#[inline]
pub const fn default_coalesce_threshold(mtu: usize) -> usize {
    mtu / 3
}

/// Attempt to combine a small outgoing `quic-mux` packet `incoming` (`incoming.bytes().len() <= coalesce_threshold`)
/// into the tail of an already-pending `target` packet for the same association.
///
/// - Requires `target_meta.association == incoming_meta.association`, `target.is_unique()`,
///   `incoming.bytes().len() <= coalesce_threshold`, and `target.bytes().len() + incoming.bytes().len() <= mtu`.
/// - On success: appends `incoming.bytes()` to `target` in-place, merges `incoming_meta` into `target_meta`
///   (promoting priority to the higher importance, OR-ing `retransmittable`, and clearing `stream_id` to
///   `None` when distinct streams are combined), drops `incoming` (returning its pool slot immediately),
///   and returns `Ok(())`.
/// - On refusal: returns `Err(incoming)` untouched.
pub fn try_coalesce_tx_packet<P: PoolPacket>(
    target_meta: &mut TxPacketMeta,
    target: &mut P,
    incoming_meta: TxPacketMeta,
    incoming: P,
    mtu: usize,
    coalesce_threshold: usize,
) -> Result<(), P> {
    let inc_len = incoming.bytes().len();
    if target_meta.association != incoming_meta.association
        || inc_len == 0
        || inc_len > coalesce_threshold
        || !target.is_unique()
        || target.bytes().len().saturating_add(inc_len) > mtu
    {
        return Err(incoming);
    }
    if target.append(incoming.bytes()).is_err() {
        return Err(incoming);
    }
    if incoming_meta.priority.is_higher_than(target_meta.priority) {
        target_meta.priority = incoming_meta.priority;
    }
    target_meta.retransmittable |= incoming_meta.retransmittable;
    if target_meta.stream_id != incoming_meta.stream_id {
        target_meta.stream_id = None;
    }
    drop(incoming);
    Ok(())
}

/// Inclusive packet-number range `[start_pkt_num ..= end_pkt_num]` in a Selective ACK (SACK).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckRange {
    /// First acknowledged packet number in the contiguous block (inclusive).
    pub start_pkt_num: u64,
    /// Last acknowledged packet number in the contiguous block (inclusive).
    pub end_pkt_num: u64,
}

impl AckRange {
    /// Create an inclusive SACK range `[start ..= end]`.
    #[inline]
    pub const fn new(start_pkt_num: u64, end_pkt_num: u64) -> Self {
        Self {
            start_pkt_num,
            end_pkt_num,
        }
    }

    /// Check whether `pkt_num` is covered by this range.
    #[inline]
    pub const fn contains(&self, pkt_num: u64) -> bool {
        pkt_num >= self.start_pkt_num && pkt_num <= self.end_pkt_num
    }
}

/// Unacknowledged packet returned by [`SackRetransmitLedger`] for retransmission across a newly
/// selected link.
#[derive(Debug)]
pub struct RetransmitCandidate<P: PoolPacket> {
    /// Original packet number that was declared lost by SACK or timeout.
    pub original_pkt_num: u64,
    /// Original TX packet metadata.
    pub meta: TxPacketMeta,
    /// Cloned `PoolPacket` lease with `range()` restored to the `quic-mux` frame boundary
    /// so the link/association layer can prepend a new packet number + link header in-place.
    pub packet: P,
}

struct RetainedTxPacket<P: PoolPacket> {
    pkt_num: u64,
    meta: TxPacketMeta,
    mux_range: Range<usize>,
    sent_at_us: u64,
    retransmitted: bool,
    packet: P,
}

/// Dynamic-capacity Selective ACK (SACK) and retransmit packet ledger for the association/link layer.
///
/// Holds unacknowledged TX `PoolPacket` leases up to a dynamically adjustable `max_retained_packets`
/// limit. When under pressure, evicts all unACKed packets belonging to the lowest-priority stream
/// (`StreamPriority` numerically largest) and returns its `(AssociationId, StreamId)` so `QuicMux`
/// can reset/terminate that stream.
pub struct SackRetransmitLedger<P: PoolPacket> {
    next_pkt_num: u64,
    max_retained_packets: usize,
    entries: VecDeque<RetainedTxPacket<P>>,
}

impl<P: PoolPacket> SackRetransmitLedger<P> {
    /// Create a new SACK/retransmit ledger with initial `max_retained_packets` limit.
    pub fn new(max_retained_packets: usize) -> Self {
        Self {
            next_pkt_num: 1,
            max_retained_packets,
            entries: VecDeque::new(),
        }
    }

    /// Current dynamic limit on retained unacknowledged TX packets.
    #[inline]
    pub const fn max_retained_packets(&self) -> usize {
        self.max_retained_packets
    }

    /// Number of unacknowledged TX packets currently retained.
    #[inline]
    pub fn retained_packets(&self) -> usize {
        self.entries.len()
    }

    /// Dynamically adjust `max_retained_packets` based on system load.
    ///
    /// If the new limit is smaller than the current number of retained packets, evicts all
    /// packets belonging to the lowest-priority stream(s) until `retained_packets() <= max_packets`,
    /// returning the evicted `(AssociationId, StreamId)` pairs so the caller can RST those streams
    /// via [`crate::mux::QuicMux::abort_stream_under_pressure`].
    pub fn set_max_retained_packets(&mut self, max_packets: usize) -> Vec<(AssociationId, StreamId)> {
        self.max_retained_packets = max_packets;
        let mut evicted_streams = Vec::new();
        while self.entries.len() > self.max_retained_packets {
            if let Some(victim) = self.select_victim_stream(None) {
                self.purge_stream(victim.0, victim.1);
                if !evicted_streams.contains(&victim) {
                    evicted_streams.push(victim);
                }
            } else {
                // Fallback: drop oldest non-stream or lowest-priority single entry
                self.entries.pop_front();
            }
        }
        evicted_streams
    }

    /// Record a transmitted packet for SACK tracking and potential retransmission.
    ///
    /// - Preserves `packet.range()` (`mux_range`) so that if the packet must be retransmitted on a
    ///   different link (with a different header size), the `quic-mux` frame is intact.
    /// - If `retained_packets() >= max_retained_packets`, attempts to evict a strictly lower-priority
    ///   stream (`victim_priority > meta.priority`).
    /// - Returns `Ok((pkt_num, evicted_streams))` if admitted, or `Err(packet)` if the ledger is full
    ///   and no lower-priority stream can be evicted.
    pub fn record_tx(
        &mut self,
        meta: TxPacketMeta,
        packet: P,
        sent_at_us: u64,
    ) -> Result<(u64, Vec<(AssociationId, StreamId)>), P> {
        let mut evicted_streams = Vec::new();
        if self.max_retained_packets == 0 {
            return Err(packet);
        }
        while self.entries.len() >= self.max_retained_packets {
            let Some(victim) = self.select_victim_stream(Some(meta.priority)) else {
                return Err(packet);
            };
            self.purge_stream(victim.0, victim.1);
            if !evicted_streams.contains(&victim) {
                evicted_streams.push(victim);
            }
        }

        let pkt_num = self.next_pkt_num;
        self.next_pkt_num += 1;
        let mux_range = packet.range();
        self.entries.push_back(RetainedTxPacket {
            pkt_num,
            meta,
            mux_range,
            sent_at_us,
            retransmitted: false,
            packet,
        });
        Ok((pkt_num, evicted_streams))
    }

    /// Process Selective ACK ranges (`ack_ranges`) for `assoc`:
    ///
    /// 1. Removes and drops all retained `PoolPacket` leases whose `pkt_num` is covered by `ack_ranges`.
    /// 2. Any remaining unACKed packet on `assoc` with `pkt_num + reordering_threshold <= largest_acked`
    ///    is marked for retransmission and returned as a [`RetransmitCandidate`] with its `range()`
    ///    restored to the `quic-mux` frame boundary.
    pub fn on_selective_ack(
        &mut self,
        assoc: AssociationId,
        ack_ranges: &[AckRange],
        reordering_threshold: u64,
    ) -> Vec<RetransmitCandidate<P>> {
        let largest_acked = ack_ranges.iter().map(|r| r.end_pkt_num).max();

        // 1. Free all selectively ACKed packets immediately
        self.entries.retain(|entry| {
            if entry.meta.association != assoc {
                return true;
            }
            !ack_ranges.iter().any(|r| r.contains(entry.pkt_num))
        });

        // 2. Collect SACK-declared lost packets below `largest_acked`
        let mut retransmits = Vec::new();
        let Some(largest) = largest_acked else {
            return retransmits;
        };

        for entry in &mut self.entries {
            if entry.meta.association == assoc
                && !entry.retransmitted
                && entry.pkt_num.saturating_add(reordering_threshold) <= largest
            {
                if let Ok(mut cloned) = entry.packet.try_clone() {
                    let _ = cloned.set_range(entry.mux_range.clone());
                    entry.retransmitted = true;
                    retransmits.push(RetransmitCandidate {
                        original_pkt_num: entry.pkt_num,
                        meta: entry.meta,
                        packet: cloned,
                    });
                }
            }
        }
        retransmits
    }

    /// Collect unacknowledged packets older than `rto_us` at `now_us` for timeout retransmission.
    pub fn collect_rto_retransmits(
        &mut self,
        now_us: u64,
        rto_us: u64,
    ) -> Vec<RetransmitCandidate<P>> {
        let mut out = Vec::new();
        for entry in &mut self.entries {
            if now_us.saturating_sub(entry.sent_at_us) >= rto_us {
                if let Ok(mut cloned) = entry.packet.try_clone() {
                    let _ = cloned.set_range(entry.mux_range.clone());
                    entry.sent_at_us = now_us;
                    entry.retransmitted = true;
                    out.push(RetransmitCandidate {
                        original_pkt_num: entry.pkt_num,
                        meta: entry.meta,
                        packet: cloned,
                    });
                }
            }
        }
        out
    }

    /// Purge all retained unACKed TX packets for `(assoc, stream_id)`, returning the number of freed packets.
    pub fn purge_stream(&mut self, assoc: AssociationId, stream_id: StreamId) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| {
            !(e.meta.association == assoc && e.meta.stream_id == Some(stream_id))
        });
        before - self.entries.len()
    }

    /// Select the lowest-priority stream (`StreamPriority` numerically largest) currently holding
    /// unACKed packets. If `must_be_lower_than` is `Some(req_prio)`, only considers streams with
    /// `entry.priority > req_prio`.
    fn select_victim_stream(
        &self,
        must_be_lower_than: Option<StreamPriority>,
    ) -> Option<(AssociationId, StreamId)> {
        let mut best: Option<(StreamPriority, AssociationId, StreamId)> = None;
        for entry in &self.entries {
            let Some(sid) = entry.meta.stream_id else {
                continue;
            };
            if let Some(req) = must_be_lower_than {
                if !entry.meta.priority.is_lower_than(req) {
                    continue;
                }
            }
            match best {
                None => best = Some((entry.meta.priority, entry.meta.association, sid)),
                Some((best_prio, _, _)) if entry.meta.priority.is_lower_than(best_prio) => {
                    best = Some((entry.meta.priority, entry.meta.association, sid));
                }
                _ => {}
            }
        }
        best.map(|(_, a, s)| (a, s))
    }
}
