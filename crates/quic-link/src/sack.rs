//! Multi-link Selective ACK (SACK) and retransmission ledger with per-link `send_order`
//! loss detection, spurious-loss adaptation, link-failure failover, and priority eviction.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ops::Range;

use quic_base::pool::PoolPacket;
use quic_base::wire::StreamId;
use quic_base::{AssociationId, StreamPriority, TxPacketMeta};

use crate::LinkMap;
use crate::congestion::{CongestionMode, LinkId, LinkState, LinkTxOutcome};
use crate::wire::AckRangeSet;

/// Unacknowledged packet returned by [`MultiLinkSackLedger`] for retransmission across any
/// ready link.
#[derive(Debug)]
pub struct LinkRetransmitCandidate<P: PoolPacket> {
    /// Original packet number that was declared lost by SACK, time threshold, PTO, or link failure.
    pub original_pkt_num: u32,
    /// Link on which the original packet was transmitted.
    pub original_link_id: LinkId,
    /// Original TX packet metadata.
    pub meta: TxPacketMeta,
    /// Cloned `PoolPacket` lease with `range()` restored to `mux_range` (the inner frame boundary
    /// prior to outer `ACK` / `ShortHeader` prepending) so it can be reframed on any link with
    /// a fresh packet number and zero payload copy.
    pub packet: P,
}

/// Summary returned after processing an incoming `ACK` frame.
#[derive(Debug)]
pub struct AckProcessOutcome<P: PoolPacket> {
    /// Number of newly acknowledged packets.
    pub newly_acked_packets: usize,
    /// Number of newly acknowledged wire bytes.
    pub newly_acked_bytes: u64,
    /// Number of previously lost-marked packets that were later acknowledged (spurious losses).
    pub spurious_losses: usize,
    /// Retransmit candidates triggered by per-link SACK packet-threshold or time-threshold loss.
    pub retransmit_candidates: Vec<LinkRetransmitCandidate<P>>,
}

struct SentPacketEntry<P: PoolPacket> {
    pkt_num: u32,
    link_id: LinkId,
    link_send_order: u64,
    wire_bytes: usize,
    sent_at_us: u64,
    mux_range: Range<usize>,
    meta: TxPacketMeta,
    window_limited: bool,
    in_flight: bool,
    declared_lost: bool,
    retransmitted: bool,
    packet: Option<P>,
}

/// Multi-link Selective ACK and retransmit ledger for one or more associations.
///
/// Key properties:
/// - **Per-link `send_order` loss detection:** When an `ACK` arrives, packet-threshold and
///   time-threshold loss checks only compare unACKed packets on `link_id` against
///   `link.largest_acked_send_order` on that *same* link. Fast ACKs on a 5 ms UDP/TCP link
///   never trigger false loss on an 80 ms PPP or 400 ms LoRa/ESP-NOW link.
/// - **Zero-copy cross-link retransmission:** Retains `mux_range` (the inner frame slice before
///   any piggybacked `ACK` or `ShortHeader` was prepended) so a lost packet can be retransmitted
///   on a different link with a different header/CID size without copying payload bytes.
/// - **Spurious-loss detection:** If a packet previously declared lost is later acknowledged,
///   its `PoolPacket` lease is freed and `LinkState::on_spurious_loss_ack` widens that link's
///   reordering threshold and time-loss ratio.
/// - **Priority-based memory pressure eviction:** Enforces `max_retained_packets`, evicting all
///   unACKed packets of the lowest-priority stream (`StreamPriority` numerically largest) when full.
pub struct MultiLinkSackLedger<P: PoolPacket> {
    max_retained_packets: usize,
    retained_packet_leases: usize,
    entries: VecDeque<SentPacketEntry<P>>,
}

impl<P: PoolPacket> MultiLinkSackLedger<P> {
    /// Create a new ledger with initial `max_retained_packets` lease capacity.
    pub fn new(max_retained_packets: usize) -> Self {
        Self {
            max_retained_packets,
            retained_packet_leases: 0,
            entries: VecDeque::new(),
        }
    }

    /// Current dynamic limit on retained `PoolPacket` leases.
    #[inline]
    pub const fn max_retained_packets(&self) -> usize {
        self.max_retained_packets
    }

    /// Number of active `PoolPacket` leases currently held in the ledger.
    #[inline]
    pub const fn retained_packets(&self) -> usize {
        self.retained_packet_leases
    }

    /// Total number of tracked sent packet entries (including entries kept as metadata after
    /// retransmission for spurious-loss detection).
    #[inline]
    pub fn tracked_entries(&self) -> usize {
        self.entries.len()
    }

    /// Dynamically adjust `max_retained_packets` based on system/pool load.
    ///
    /// If the new limit is smaller than `retained_packets()`, evicts all unACKed packets belonging
    /// to the lowest-priority stream(s) until `retained_packets() <= max_packets` (releasing their
    /// in-flight bytes on `links`), and returns the evicted `(AssociationId, StreamId)` pairs.
    pub fn set_max_retained_packets(
        &mut self,
        max_packets: usize,
        links: &mut LinkMap<LinkId, LinkState>,
    ) -> Vec<(AssociationId, StreamId)> {
        self.max_retained_packets = max_packets;
        let mut evicted_streams = Vec::new();
        while self.retained_packet_leases > self.max_retained_packets {
            if let Some(victim) = self.select_victim_stream(None) {
                self.purge_stream(victim.0, victim.1, links);
                if !evicted_streams.contains(&victim) {
                    evicted_streams.push(victim);
                }
            } else if !self.drop_oldest_leased_entry(links) {
                break;
            }
        }
        evicted_streams
    }

    /// Check whether a packet with `priority` can be admitted into the retransmit ledger
    /// (either below `max_retained_packets` or by evicting a strictly lower-priority stream).
    pub fn can_admit(&self, priority: StreamPriority) -> bool {
        if self.max_retained_packets == 0 {
            return false;
        }
        if self.retained_packet_leases < self.max_retained_packets {
            return true;
        }
        self.select_victim_stream(Some(priority)).is_some()
    }

    /// Record a transmitted packet in the ledger.
    ///
    /// - `mux_range` is the inner `quic-mux` / `STREAM` frame slice prior to prepending any
    ///   piggybacked `ACK` or outer `ShortHeader`.
    /// - If `meta.retransmittable` is true, holds `Some(packet)` against `max_retained_packets`
    ///   (evicting lower-priority streams if needed).
    pub fn record_tx(
        &mut self,
        pkt_num: u32,
        link_id: LinkId,
        link_send_order: u64,
        wire_bytes: usize,
        sent_at_us: u64,
        mux_range: Range<usize>,
        meta: TxPacketMeta,
        window_limited: bool,
        packet: Option<P>,
        links: &mut LinkMap<LinkId, LinkState>,
    ) -> Result<Vec<(AssociationId, StreamId)>, P> {
        let mut evicted_streams = Vec::new();
        if let Some(pkt) = packet {
            if self.max_retained_packets == 0 {
                return Err(pkt);
            }
            while self.retained_packet_leases >= self.max_retained_packets {
                let Some(victim) = self.select_victim_stream(Some(meta.priority)) else {
                    return Err(pkt);
                };
                self.purge_stream(victim.0, victim.1, links);
                if !evicted_streams.contains(&victim) {
                    evicted_streams.push(victim);
                }
            }
            self.retained_packet_leases += 1;
            self.entries.push_back(SentPacketEntry {
                pkt_num,
                link_id,
                link_send_order,
                wire_bytes,
                sent_at_us,
                mux_range,
                meta,
                window_limited,
                in_flight: true,
                declared_lost: false,
                retransmitted: false,
                packet: Some(pkt),
            });
        } else {
            // Non-retransmittable ack-eliciting packet (e.g. DATAGRAM or PING): track metadata for
            // RTT and in-flight byte accounting without retaining a PoolPacket lease.
            if self.entries.len() >= self.max_retained_packets.saturating_mul(2).max(64) {
                self.prune_retired_metadata();
            }
            self.entries.push_back(SentPacketEntry {
                pkt_num,
                link_id,
                link_send_order,
                wire_bytes,
                sent_at_us,
                mux_range,
                meta,
                window_limited,
                in_flight: true,
                declared_lost: false,
                retransmitted: true,
                packet: None,
            });
        }
        Ok(evicted_streams)
    }

    /// Process an incoming `ACK` frame (`ranges`, `delay_us`) at `now_us`:
    ///
    /// 1. Identifies newly acknowledged packets, updates per-link `largest_acked_send_order` and
    ///    `largest_acked_packet`, updates per-link `RttEstimator` from the newest newly-ACKed
    ///    packet on each link, credits `LinkState::congestion.on_ack`, and frees `PoolPacket` leases.
    /// 2. Detects spurious losses (when a packet with `declared_lost == true` is acknowledged) and
    ///    calls `LinkState::on_spurious_loss_ack`.
    /// 3. Runs per-link packet-threshold (`send_order + threshold <= link.largest_acked_send_order`)
    ///    and time-threshold (`now_us - sent_at_us >= link.loss_delay_us(max_ack_delay_us)`) loss
    ///    detection, returning `LinkRetransmitCandidate<P>` items ready for retransmission.
    pub fn on_ack_frame(
        &mut self,
        ranges: &AckRangeSet,
        delay_us: u64,
        max_ack_delay_us: u64,
        now_us: u64,
        links: &mut LinkMap<LinkId, LinkState>,
    ) -> AckProcessOutcome<P> {
        let mut newly_acked_packets = 0usize;
        let mut newly_acked_bytes = 0u64;
        let mut spurious_losses = 0usize;

        // Track newest newly-ACKed packet per link `(pkt_num, sent_at_us)` for RTT sampling.
        let mut newest_rtt_sample_per_link: LinkMap<LinkId, (u32, u64)> = LinkMap::new();

        for i in (0..self.entries.len()).rev() {
            let pkt_num = self.entries[i].pkt_num;
            if !ranges.contains(pkt_num) {
                continue;
            }
            let entry = self.entries.remove(i).unwrap();
            if entry.packet.is_some() {
                self.retained_packet_leases = self.retained_packet_leases.saturating_sub(1);
            }
            newly_acked_packets += 1;
            newly_acked_bytes = newly_acked_bytes.saturating_add(entry.wire_bytes as u64);

            if let Some(link) = links.get_mut(&entry.link_id) {
                link.stats.packets_acked += 1;
                link.pto_backoff = 0;
                link.largest_acked_packet = Some(
                    link.largest_acked_packet
                        .map_or(entry.pkt_num, |prev| prev.max(entry.pkt_num)),
                );
                link.largest_acked_send_order = Some(
                    link.largest_acked_send_order
                        .map_or(entry.link_send_order, |prev| prev.max(entry.link_send_order)),
                );

                if entry.declared_lost {
                    spurious_losses += 1;
                    link.on_spurious_loss_ack(entry.link_send_order, entry.sent_at_us, now_us);
                } else if entry.in_flight {
                    link.packets_in_flight = link.packets_in_flight.saturating_sub(1);
                    let allow_growth = match link.profile.congestion_mode {
                        CongestionMode::NewRenoPaced { .. } => {
                            entry.window_limited
                                || link.congestion.congestion_window
                                    < link.congestion.slow_start_threshold
                        }
                        _ => false,
                    };
                    link.congestion.on_ack(entry.wire_bytes as u64, allow_growth);
                }

                if let Some(cur) = newest_rtt_sample_per_link.get_mut(&entry.link_id) {
                    if entry.pkt_num > cur.0 {
                        *cur = (entry.pkt_num, entry.sent_at_us);
                    }
                } else {
                    newest_rtt_sample_per_link.insert(entry.link_id, (entry.pkt_num, entry.sent_at_us));
                }
            }
        }

        // Apply RTT samples from the newest newly-acknowledged packet on each link.
        let capped_delay = delay_us.min(max_ack_delay_us);
        for (link_id, (_pn, sent_at)) in newest_rtt_sample_per_link {
            if let Some(link) = links.get_mut(&link_id) {
                let raw_rtt = now_us.saturating_sub(sent_at);
                let adjusted_rtt = if raw_rtt > capped_delay {
                    raw_rtt - capped_delay
                } else {
                    raw_rtt
                };
                link.rtt.update_at(adjusted_rtt.max(1), now_us);
            }
        }

        // Per-link packet-threshold and time-threshold loss detection.
        let retransmit_candidates = self.detect_losses(max_ack_delay_us, now_us, links);

        AckProcessOutcome {
            newly_acked_packets,
            newly_acked_bytes,
            spurious_losses,
            retransmit_candidates,
        }
    }

    /// Run per-link packet-threshold and time-threshold loss detection at `now_us`.
    pub fn detect_losses(
        &mut self,
        max_ack_delay_us: u64,
        now_us: u64,
        links: &mut LinkMap<LinkId, LinkState>,
    ) -> Vec<LinkRetransmitCandidate<P>> {
        let mut candidates = Vec::new();
        for entry in &mut self.entries {
            if entry.declared_lost {
                continue;
            }
            let Some(link) = links.get_mut(&entry.link_id) else {
                continue;
            };
            let Some(largest_acked_order) = link.largest_acked_send_order else {
                continue;
            };
            if entry.link_send_order >= largest_acked_order {
                continue;
            }

            let packet_threshold_lost = entry
                .link_send_order
                .saturating_add(link.packet_reordering_threshold)
                <= largest_acked_order;
            let loss_delay = link.loss_delay_us(max_ack_delay_us);
            let time_threshold_lost = now_us.saturating_sub(entry.sent_at_us) >= loss_delay;

            if !packet_threshold_lost && !time_threshold_lost {
                continue;
            }

            let mut cloned_pkt = None;
            if !entry.retransmitted {
                if let Some(mut pkt) = entry.packet.take() {
                    if pkt.is_unique() {
                        self.retained_packet_leases = self.retained_packet_leases.saturating_sub(1);
                        let _ = pkt.set_range(entry.mux_range.clone());
                        cloned_pkt = Some(pkt);
                    } else {
                        // Driver still holds a reference; restore `entry.packet` and retry on next poll.
                        entry.packet = Some(pkt);
                        continue;
                    }
                }
            }

            entry.declared_lost = true;
            if entry.in_flight {
                entry.in_flight = false;
                link.packets_in_flight = link.packets_in_flight.saturating_sub(1);
                link.stats.packets_lost += 1;
                match link.profile.congestion_mode {
                    CongestionMode::NewRenoPaced { .. } => {
                        let largest_sent = link.largest_sent_packet.unwrap_or(entry.pkt_num);
                        link.congestion.on_packet_lost(
                            entry.wire_bytes as u64,
                            entry.pkt_num,
                            largest_sent,
                        );
                    }
                    CongestionMode::FlowControlled { .. } | CongestionMode::Radio { .. } => {
                        link.congestion.remove_in_flight(entry.wire_bytes as u64);
                    }
                }
            }

            if let Some(restored) = cloned_pkt {
                entry.retransmitted = true;
                candidates.push(LinkRetransmitCandidate {
                    original_pkt_num: entry.pkt_num,
                    original_link_id: entry.link_id,
                    meta: entry.meta,
                    packet: restored,
                });
            }
        }
        candidates
    }

    /// Collect PTO (Probe Timeout) retransmit candidates at `now_us` for any link whose oldest
    /// unacknowledged packet has exceeded `link.pto_timeout_us(max_ack_delay_us)`.
    pub fn collect_pto_retransmits(
        &mut self,
        max_ack_delay_us: u64,
        now_us: u64,
        links: &mut LinkMap<LinkId, LinkState>,
    ) -> Vec<LinkRetransmitCandidate<P>> {
        let mut out = Vec::new();
        for entry in &mut self.entries {
            if entry.retransmitted {
                continue;
            }
            let Some(link) = links.get_mut(&entry.link_id) else {
                continue;
            };
            let pto_us = link.pto_timeout_us(max_ack_delay_us);
            if now_us.saturating_sub(entry.sent_at_us) < pto_us {
                continue;
            }

            let mut cloned_pkt = None;
            if let Some(mut pkt) = entry.packet.take() {
                if pkt.is_unique() {
                    self.retained_packet_leases = self.retained_packet_leases.saturating_sub(1);
                    let _ = pkt.set_range(entry.mux_range.clone());
                    cloned_pkt = Some(pkt);
                } else {
                    // Driver still holds a reference; restore `entry.packet` and retry on next poll_timers.
                    entry.packet = Some(pkt);
                    continue;
                }
            }
            if entry.in_flight {
                entry.in_flight = false;
                link.packets_in_flight = link.packets_in_flight.saturating_sub(1);
                link.congestion.remove_in_flight(entry.wire_bytes as u64);
            }
            entry.declared_lost = true;
            link.pto_backoff = (link.pto_backoff + 1).min(3);

            if let Some(restored) = cloned_pkt {
                entry.retransmitted = true;
                out.push(LinkRetransmitCandidate {
                    original_pkt_num: entry.pkt_num,
                    original_link_id: entry.link_id,
                    meta: entry.meta,
                    packet: restored,
                });
            }
        }
        out
    }

    /// Handle physical driver completion for `pkt_num`:
    /// - If `LinkTxOutcome::Failed`, releases in-flight bytes on that link without halving `cwnd`
    ///   and immediately returns the packet as a `LinkRetransmitCandidate` for failover onto
    ///   another link.
    pub fn on_driver_complete(
        &mut self,
        pkt_num: u32,
        outcome: LinkTxOutcome,
        links: &mut LinkMap<LinkId, LinkState>,
    ) -> Option<LinkRetransmitCandidate<P>> {
        if outcome != LinkTxOutcome::Failed {
            return None;
        }
        let idx = self.entries.iter().position(|e| e.pkt_num == pkt_num)?;
        let mut entry = self.entries.remove(idx)?;
        if let Some(link) = links.get_mut(&entry.link_id) {
            if entry.in_flight {
                link.packets_in_flight = link.packets_in_flight.saturating_sub(1);
                link.congestion.remove_in_flight(entry.wire_bytes as u64);
            }
        }
        let mut pkt = entry.packet.take()?;
        self.retained_packet_leases = self.retained_packet_leases.saturating_sub(1);
        let _ = pkt.set_range(entry.mux_range);
        Some(LinkRetransmitCandidate {
            original_pkt_num: entry.pkt_num,
            original_link_id: entry.link_id,
            meta: entry.meta,
            packet: pkt,
        })
    }

    /// Evacuate all unacknowledged packets from `failed_link_id` (e.g. when a TCP connection drops
    /// or a radio/serial bearer is suspended), releasing in-flight counters on `failed_link_id` and
    /// returning all retransmittable packets for immediate failover onto remaining links.
    pub fn evacuate_link(
        &mut self,
        failed_link_id: LinkId,
        links: &mut LinkMap<LinkId, LinkState>,
    ) -> Vec<LinkRetransmitCandidate<P>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.entries.len() {
            if self.entries[i].link_id != failed_link_id {
                i += 1;
                continue;
            }
            let mut entry = self.entries.remove(i).unwrap();
            if let Some(link) = links.get_mut(&failed_link_id) {
                if entry.in_flight {
                    link.packets_in_flight = link.packets_in_flight.saturating_sub(1);
                    link.congestion.remove_in_flight(entry.wire_bytes as u64);
                }
            }
            if let Some(mut pkt) = entry.packet.take() {
                self.retained_packet_leases = self.retained_packet_leases.saturating_sub(1);
                let _ = pkt.set_range(entry.mux_range);
                out.push(LinkRetransmitCandidate {
                    original_pkt_num: entry.pkt_num,
                    original_link_id: failed_link_id,
                    meta: entry.meta,
                    packet: pkt,
                });
            }
        }
        out
    }

    /// Purge all retained unACKed TX packets for `(assoc, stream_id)`, releasing their `PoolPacket`
    /// leases and in-flight bytes on `links`.
    pub fn purge_stream(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        links: &mut LinkMap<LinkId, LinkState>,
    ) -> usize {
        let mut freed = 0usize;
        let mut i = 0;
        while i < self.entries.len() {
            let matches = self.entries[i].meta.association == assoc
                && self.entries[i].meta.stream_id == Some(stream_id);
            if !matches {
                i += 1;
                continue;
            }
            let entry = self.entries.remove(i).unwrap();
            if entry.packet.is_some() {
                self.retained_packet_leases = self.retained_packet_leases.saturating_sub(1);
                freed += 1;
            }
            if entry.in_flight {
                if let Some(link) = links.get_mut(&entry.link_id) {
                    link.packets_in_flight = link.packets_in_flight.saturating_sub(1);
                    link.congestion.remove_in_flight(entry.wire_bytes as u64);
                }
            }
        }
        freed
    }

    /// Next earliest loss or PTO timer deadline across all unacknowledged packets.
    pub fn next_deadline_us(
        &self,
        max_ack_delay_us: u64,
        links: &LinkMap<LinkId, LinkState>,
    ) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        for entry in &self.entries {
            if entry.retransmitted || (entry.declared_lost && entry.packet.is_none()) {
                continue;
            }
            let Some(link) = links.get(&entry.link_id) else {
                continue;
            };
            let deadline = if let Some(largest_order) = link.largest_acked_send_order {
                if !entry.declared_lost && entry.link_send_order < largest_order {
                    entry
                        .sent_at_us
                        .saturating_add(link.loss_delay_us(max_ack_delay_us))
                } else {
                    entry
                        .sent_at_us
                        .saturating_add(link.pto_timeout_us(max_ack_delay_us))
                }
            } else {
                entry
                    .sent_at_us
                    .saturating_add(link.pto_timeout_us(max_ack_delay_us))
            };
            earliest = Some(earliest.map_or(deadline, |cur| cur.min(deadline)));
        }
        earliest
    }

    fn select_victim_stream(
        &self,
        must_be_lower_than: Option<StreamPriority>,
    ) -> Option<(AssociationId, StreamId)> {
        let mut best: Option<(StreamPriority, AssociationId, StreamId)> = None;
        for entry in &self.entries {
            if entry.packet.is_none() {
                continue;
            }
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

    fn drop_oldest_leased_entry(&mut self, links: &mut LinkMap<LinkId, LinkState>) -> bool {
        let Some(idx) = self.entries.iter().position(|e| e.packet.is_some()) else {
            return false;
        };
        let entry = self.entries.remove(idx).unwrap();
        self.retained_packet_leases = self.retained_packet_leases.saturating_sub(1);
        if entry.in_flight {
            if let Some(link) = links.get_mut(&entry.link_id) {
                link.packets_in_flight = link.packets_in_flight.saturating_sub(1);
                link.congestion.remove_in_flight(entry.wire_bytes as u64);
            }
        }
        true
    }

    fn prune_retired_metadata(&mut self) {
        if let Some(idx) = self
            .entries
            .iter()
            .position(|e| e.packet.is_none() && (!e.in_flight || e.declared_lost))
        {
            self.entries.remove(idx);
        }
    }
}
