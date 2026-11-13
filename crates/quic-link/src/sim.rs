//! Deterministic virtual-clock multi-link network simulator for testing `quic-link` and `quic-mux`
//! across heterogeneous bearers (UDP, TCP/PPP streams, LoRa, and multicast/unicast ESP-NOW).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use quic_base::pool::PoolPacket;

use crate::congestion::{LinkId, LinkTxOutcome};

/// Endpoint direction inside [`SimNetwork`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SimSide {
    /// Endpoint A (e.g. client / local node).
    A,
    /// Endpoint B (e.g. server / remote node).
    B,
}

impl SimSide {
    /// Opposite endpoint side.
    #[inline]
    pub const fn peer(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// Physical medium parameters for one simulated link in [`SimNetwork`].
#[derive(Clone, Copy, Debug)]
pub struct SimLinkSpec {
    /// Link identifier on both endpoints.
    pub link_id: LinkId,
    /// Base one-way propagation delay in microseconds.
    pub one_way_delay_us: u64,
    /// Maximum random jitter added to one-way delay in microseconds (`0` = no jitter / in-order medium).
    pub jitter_us: u64,
    /// Serialization time per packet in microseconds (e.g. radio airtime or slow serial line).
    pub serialization_us_per_packet: u64,
    /// Whether the physical link is half-duplex (A->B and B->A share the same airtime serializer,
    /// e.g. LoRa or single-channel ESP-NOW).
    pub half_duplex: bool,
    /// Whether the physical link lacks per-packet L2 MAC ACKs (e.g. LoRa or multicast ESP-NOW).
    /// When `has_mac_ack == false`, local driver completion is always `LinkTxOutcome::Sent` even
    /// if the packet is lost in the air!
    pub has_mac_ack: bool,
    /// Random packet loss rate in parts per `10_000` (`0` = 0%, `2000` = 20%).
    pub loss_ppm_10k: u16,
    /// Optional burst loss length when a loss event triggers (`1` = independent single-packet loss).
    pub loss_burst_len: u8,
    /// Whether the link is currently physically up.
    pub up: bool,
}

impl SimLinkSpec {
    /// Fast low-latency UDP link (`5 ms` one-way delay).
    pub const fn fast_udp(link_id: LinkId) -> Self {
        Self {
            link_id,
            one_way_delay_us: 5_000,
            jitter_us: 0,
            serialization_us_per_packet: 100,
            half_duplex: false,
            has_mac_ack: false,
            loss_ppm_10k: 0,
            loss_burst_len: 1,
            up: true,
        }
    }

    /// Slower PPP / serial or cellular link (`80 ms` one-way delay).
    pub const fn slow_ppp(link_id: LinkId) -> Self {
        Self {
            link_id,
            one_way_delay_us: 80_000,
            jitter_us: 0,
            serialization_us_per_packet: 2_000,
            half_duplex: false,
            has_mac_ack: true,
            loss_ppm_10k: 0,
            loss_burst_len: 1,
            up: true,
        }
    }

    /// Long-range LoRa or multicast ESP-NOW link **without** L2 MAC ACKs (`120 ms` airtime, half-duplex).
    pub const fn lora_no_mac_ack(link_id: LinkId, loss_ppm_10k: u16) -> Self {
        Self {
            link_id,
            one_way_delay_us: 120_000,
            jitter_us: 5_000,
            serialization_us_per_packet: 100_000,
            half_duplex: true,
            has_mac_ack: false,
            loss_ppm_10k,
            loss_burst_len: 1,
            up: true,
        }
    }
}

/// Packet delivered by [`SimNetwork::step_to`].
#[derive(Debug)]
pub struct SimDelivery<P: PoolPacket> {
    /// Destination endpoint (`A` or `B`).
    pub recipient: SimSide,
    /// Link on which the packet arrived.
    pub link_id: LinkId,
    /// Monotonic delivery timestamp in microseconds.
    pub delivered_at_us: u64,
    /// Delivered `PoolPacket` (with `range()` covering the wire packet starting at `ShortHeader`).
    pub packet: P,
}

/// Driver completion notification emitted by [`SimNetwork`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimDriverEvent {
    /// Sender endpoint (`A` or `B`).
    pub sender: SimSide,
    /// Link on which transmission finished.
    pub link_id: LinkId,
    /// Packet number whose physical transmission completed.
    pub packet_number: u32,
    /// Timestamp of completion.
    pub completed_at_us: u64,
    /// Physical completion outcome (`Sent` or `Failed`).
    pub outcome: LinkTxOutcome,
}

struct InFlightSimPacket<P: PoolPacket> {
    recipient: SimSide,
    link_id: LinkId,
    deliver_at_us: u64,
    packet: P,
}

struct SimLinkRuntime {
    spec: SimLinkSpec,
    next_free_a_to_b_us: u64,
    next_free_b_to_a_us: u64,
    next_free_shared_us: u64,
    remaining_burst_drops: u8,
    tx_count: u64,
    dropped_count: u64,
}

/// Deterministic PRNG (xorshift64*) for reproducible loss bursts and jitter.
#[derive(Clone, Copy, Debug)]
pub struct SimRng(u64);

impl SimRng {
    /// Create a seeded `SimRng`.
    pub const fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9e37_79b9_7f4a_7c15 } else { seed })
    }

    /// Generate the next `u64`.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Generate a uniform value in `0..bound`.
    pub fn next_bounded(&mut self, bound: u64) -> u64 {
        if bound <= 1 {
            0
        } else {
            self.next_u64() % bound
        }
    }
}

/// Deterministic virtual-clock multi-link network simulator.
pub struct SimNetwork<P: PoolPacket> {
    now_us: u64,
    rng: SimRng,
    links: BTreeMap<LinkId, SimLinkRuntime>,
    in_flight: Vec<InFlightSimPacket<P>>,
    driver_events: VecDeque<SimDriverEvent>,
}

impl<P: PoolPacket> SimNetwork<P> {
    /// Create a new `SimNetwork` with deterministic `seed`.
    pub fn new(seed: u64) -> Self {
        Self {
            now_us: 0,
            rng: SimRng::new(seed),
            links: BTreeMap::new(),
            in_flight: Vec::new(),
            driver_events: VecDeque::new(),
        }
    }

    /// Current virtual clock in microseconds.
    #[inline]
    pub const fn now_us(&self) -> u64 {
        self.now_us
    }

    /// Add or update a simulated physical link.
    pub fn add_link(&mut self, spec: SimLinkSpec) {
        self.links.insert(
            spec.link_id,
            SimLinkRuntime {
                spec,
                next_free_a_to_b_us: self.now_us,
                next_free_b_to_a_us: self.now_us,
                next_free_shared_us: self.now_us,
                remaining_burst_drops: 0,
                tx_count: 0,
                dropped_count: 0,
            },
        );
    }

    /// Mutate the [`SimLinkSpec`] of `link_id` (e.g. to take a link down or change loss rate mid-test).
    pub fn link_spec_mut(&mut self, link_id: LinkId) -> Option<&mut SimLinkSpec> {
        self.links.get_mut(&link_id).map(|rt| &mut rt.spec)
    }

    /// Total packets transmitted and dropped on `link_id`.
    pub fn link_counters(&self, link_id: LinkId) -> Option<(u64, u64)> {
        self.links
            .get(&link_id)
            .map(|rt| (rt.tx_count, rt.dropped_count))
    }

    /// Enqueue a wire packet transmitted by `sender` on `link_id` with `packet_number`.
    pub fn transmit(
        &mut self,
        sender: SimSide,
        link_id: LinkId,
        packet_number: u32,
        packet: P,
    ) {
        let Some(rt) = self.links.get_mut(&link_id) else {
            self.driver_events.push_back(SimDriverEvent {
                sender,
                link_id,
                packet_number,
                completed_at_us: self.now_us,
                outcome: LinkTxOutcome::Failed,
            });
            return;
        };

        if !rt.spec.up {
            self.driver_events.push_back(SimDriverEvent {
                sender,
                link_id,
                packet_number,
                completed_at_us: self.now_us,
                outcome: LinkTxOutcome::Failed,
            });
            return;
        }

        rt.tx_count += 1;

        // Compute serialization finish time.
        let start_us = if rt.spec.half_duplex {
            self.now_us.max(rt.next_free_shared_us)
        } else {
            match sender {
                SimSide::A => self.now_us.max(rt.next_free_a_to_b_us),
                SimSide::B => self.now_us.max(rt.next_free_b_to_a_us),
            }
        };
        let tx_done_us = start_us.saturating_add(rt.spec.serialization_us_per_packet);
        if rt.spec.half_duplex {
            rt.next_free_shared_us = tx_done_us;
        } else {
            match sender {
                SimSide::A => rt.next_free_a_to_b_us = tx_done_us,
                SimSide::B => rt.next_free_b_to_a_us = tx_done_us,
            }
        }

        // Determine whether the packet is dropped in the medium.
        let dropped = if rt.remaining_burst_drops > 0 {
            rt.remaining_burst_drops -= 1;
            true
        } else if rt.spec.loss_ppm_10k > 0
            && (self.rng.next_bounded(10_000) as u16) < rt.spec.loss_ppm_10k
        {
            rt.remaining_burst_drops = rt.spec.loss_burst_len.saturating_sub(1);
            true
        } else {
            false
        };

        if dropped {
            rt.dropped_count += 1;
            // Crucial hardware realism:
            // - On LoRa or multicast ESP-NOW (`has_mac_ack == false`), the sender has NO idea the
            //   packet was lost in the air; its local radio reports `LinkTxOutcome::Sent`!
            // - On unicast MAC-ACKed links (`has_mac_ack == true`), the sender learns `Failed`.
            let outcome = if rt.spec.has_mac_ack {
                LinkTxOutcome::Failed
            } else {
                LinkTxOutcome::Sent
            };
            self.driver_events.push_back(SimDriverEvent {
                sender,
                link_id,
                packet_number,
                completed_at_us: tx_done_us,
                outcome,
            });
            return;
        }

        self.driver_events.push_back(SimDriverEvent {
            sender,
            link_id,
            packet_number,
            completed_at_us: tx_done_us,
            outcome: LinkTxOutcome::Sent,
        });

        let jitter = if rt.spec.jitter_us > 0 {
            self.rng.next_bounded(rt.spec.jitter_us + 1)
        } else {
            0
        };
        let deliver_at_us = tx_done_us
            .saturating_add(rt.spec.one_way_delay_us)
            .saturating_add(jitter);

        self.in_flight.push(InFlightSimPacket {
            recipient: sender.peer(),
            link_id,
            deliver_at_us,
            packet,
        });
    }

    /// Pop any driver completion events due at or before `self.now_us`.
    pub fn drain_due_driver_events(&mut self) -> Vec<SimDriverEvent> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.driver_events.len() {
            if self.driver_events[i].completed_at_us <= self.now_us {
                out.push(self.driver_events.remove(i).unwrap());
            } else {
                i += 1;
            }
        }
        out
    }

    /// Advance virtual time to `target_us` and return all packets delivered up to `target_us`
    /// ordered by `deliver_at_us`.
    pub fn step_to(&mut self, target_us: u64) -> Vec<SimDelivery<P>> {
        self.now_us = self.now_us.max(target_us);
        let mut due_indices: Vec<usize> = self
            .in_flight
            .iter()
            .enumerate()
            .filter_map(|(i, p)| (p.deliver_at_us <= self.now_us).then_some(i))
            .collect();
        // Extract from back to front so indices stay valid, then sort by `deliver_at_us`.
        let mut delivered = Vec::with_capacity(due_indices.len());
        for &idx in due_indices.iter().rev() {
            let pkt = self.in_flight.swap_remove(idx);
            delivered.push(SimDelivery {
                recipient: pkt.recipient,
                link_id: pkt.link_id,
                delivered_at_us: pkt.deliver_at_us,
                packet: pkt.packet,
            });
        }
        delivered.sort_by_key(|d| d.delivered_at_us);
        due_indices.clear();
        delivered
    }

    /// Earliest pending packet delivery or driver event timestamp in the simulator.
    pub fn next_event_us(&self) -> Option<u64> {
        let next_pkt = self.in_flight.iter().map(|p| p.deliver_at_us).min();
        let next_drv = self.driver_events.iter().map(|e| e.completed_at_us).min();
        match (next_pkt, next_drv) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }
}
