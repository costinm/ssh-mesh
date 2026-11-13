//! Per-link RTT estimation, congestion control profiles (`FlowControlled`, `NewRenoPaced`, `Radio`),
//! Q16 token-bucket pacing, and link scheduling metadata.

use core::cmp::min;
use quic_base::StreamPriority;

/// Identifier of an attached physical or logical link within an association.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkId(pub u16);

/// Physical/transport completion outcome reported by a bearer when a packet transmission finishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkTxOutcome {
    /// Complete packet was handed to the physical medium (e.g. radio airtime finished or socket sent).
    /// Note: For LoRa / multicast ESP-NOW / UDP, `Sent` means local transmission completed, NOT that
    /// the peer received the packet (end-to-end SACKs confirm peer receipt).
    Sent,
    /// Local transport definitely failed to transmit the packet (e.g. link down, queue flushed, or
    /// unicast MAC retry exhausted before airtime). Releases in-flight bytes on this link without
    /// halving NewReno `cwnd` and immediately marks the packet for failover retransmission.
    Failed,
    /// Ambiguous outcome; packet remains in flight until SACK or PTO resolves it.
    Indeterminate,
}

/// Link framing & encryption policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkFraming {
    /// Datagram bearer (UDP, ESP-NOW, NAN, LoRa, UnixDatagram):
    /// Carries outer `ShortHeader` (`flags | dcid | pn`) + inner frames (`ACK`, `DATAGRAM`, `STREAM`).
    Datagram {
        /// Destination CID to encode in outgoing `ShortHeader`s on this link.
        peer_cid: crate::wire::ConnectionId,
    },
    /// Dedicated byte-stream link (single-association TCP / mTLS, UDS stream, or PPP serial):
    /// Carries compact `ShortHeader` (`flags | 1-byte dcid | pn`) followed by self-delimiting frames
    /// (`STREAM` with `0x02` length bit, `DATAGRAM` `0x31` with length, `ACK` `0x02`).
    SelfDelimitingStream {
        /// Compact 1-byte CID (`0..=127`) used in the header.
        peer_cid: crate::wire::ConnectionId,
    },
}

impl Default for LinkFraming {
    fn default() -> Self {
        Self::Datagram {
            peer_cid: crate::wire::ConnectionId::new(1).unwrap(),
        }
    }
}

/// Token-bucket pacing configuration (ported from `quic-lite::PacingConfig`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacingConfig {
    /// Whether paced admission is active on this link.
    pub enabled: bool,
    /// Maximum packets emitted in a burst without waiting for paced refill.
    pub max_burst_packets: u16,
    /// Maximum wire bytes emitted in a burst without waiting for paced refill.
    pub max_burst_bytes: u32,
}

impl PacingConfig {
    /// Host UDP defaults (`8` packets burst).
    pub const fn host(mtu: usize) -> Self {
        Self {
            enabled: true,
            max_burst_packets: 8,
            max_burst_bytes: (mtu * 8) as u32,
        }
    }

    /// Low-memory embedded defaults (`4` packets burst).
    pub const fn embedded(mtu: usize) -> Self {
        Self {
            enabled: true,
            max_burst_packets: 4,
            max_burst_bytes: (mtu * 4) as u32,
        }
    }

    /// Disabled pacing.
    pub const fn disabled(mtu: usize) -> Self {
        Self {
            enabled: false,
            max_burst_packets: 64,
            max_burst_bytes: (mtu * 64) as u32,
        }
    }
}

impl Default for PacingConfig {
    fn default() -> Self {
        Self::host(1200)
    }
}

/// Congestion and admission mode tailored to the physical link class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CongestionMode {
    /// **Kernel or Hardware Flow-Controlled Link (TCP, UDS, PPP/UART, USB, BLE CoC):**
    /// - Relies on local ring/socket readiness + an upper bound on unacknowledged in-flight bytes/packets
    ///   (preventing bufferbloat in middle TCP proxies or UART rings).
    /// - No artificial NewReno slow-start or packet-loss window halving.
    FlowControlled {
        /// Maximum unacknowledged bytes allowed in flight on this link.
        max_inflight_bytes: u64,
        /// Maximum unacknowledged packets allowed in flight on this link.
        max_inflight_packets: usize,
    },

    /// **High-Rate Uncontrolled Datagram Link (UDP over Wi-Fi / Ethernet / Internet):**
    /// - Full RFC 9002 NewReno congestion controller (`cwnd`, `ssthresh`, recovery epochs, persistent
    ///   congestion collapse) + Q16 token-bucket pacer driven by `cwnd / smoothed_rtt`.
    NewRenoPaced {
        /// Initial congestion window in bytes (`0` selects RFC 9002 default `10 * mtu` clamped to `14,720`).
        initial_window_bytes: u64,
        /// Token-bucket pacing parameters.
        pacing: PacingConfig,
    },

    /// **Shared-Medium / Duty-Cycled Radio Link (LoRa, multicast/unicast ESP-NOW, NAN):**
    /// - Designed for links that may **not** have per-packet MAC ACKs (e.g. LoRa, or multicast ESP-NOW
    ///   used at long range to skip 802.11 ACK timeouts and rely on end-to-end QUIC SACKs).
    /// - Enforces a strict in-flight packet cap (`max_inflight_packets`, e.g. `1..8`), a minimum
    ///   inter-packet airtime interval (`min_interval_us`), and a minimum PTO floor (`min_pto_us`)
    ///   matching radio serialization time so packets are never retransmitted while still in the air.
    /// - Does not halve `cwnd` on isolated radio losses.
    Radio {
        /// Maximum unacknowledged packets in flight on this radio link (`1..=16`).
        max_inflight_packets: usize,
        /// Maximum concurrent packets handed to the radio peripheral before local `Sent` completion (`1..=4`).
        max_driver_queue_packets: usize,
        /// Minimum airtime / duty-cycle interval between consecutive transmissions in microseconds.
        min_interval_us: u64,
        /// Minimum PTO floor in microseconds (accounting for half-duplex radio airtime + turnaround).
        min_pto_us: u64,
    },
}

/// Per-link configuration profile for an association.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkProfile {
    /// Cost tier (`0` = fastest/cheapest local link, `1` = Wi-Fi UDP/TCP, `2` = PPP/UART/BLE, `3` = LoRa/ESP-NOW).
    /// Lower tiers are preferred; higher tiers are used only when lower tiers are unavailable, full with
    /// worse estimated arrival time, or during failover retransmission.
    pub tier: u8,
    /// Maximum wire packet size (MTU) supported by this link.
    pub mtu: usize,
    /// Lowest importance (numerically largest [`StreamPriority`]) admitted onto this link for normal
    /// transmissions.
    ///
    /// Example: Setting `max_priority: StreamPriority::NORMAL` (`128`) on a LoRa or ESP-NOW link
    /// allows `CRITICAL` (`0`), `HIGH` (`64`), and `NORMAL` (`128`) short messaging streams and
    /// high-priority datagrams, while blocking `LOW` (`192`) and `BULK` (`255`) streams/log datagrams.
    pub max_priority: StreamPriority,
    /// Framing mode (`Datagram` vs `SelfDelimitingStream`).
    pub framing: LinkFraming,
    /// Congestion and pacing mode for this link.
    pub congestion_mode: CongestionMode,
    /// Initial RTT estimate in microseconds before the first ACK sample arrives.
    pub initial_rtt_us: u64,
}

impl LinkProfile {
    /// Profile for a local or gateway TCP / UDS / high-speed PPP stream link.
    pub const fn stream_link(tier: u8, mtu: usize, max_inflight_bytes: u64) -> Self {
        Self {
            tier,
            mtu,
            max_priority: StreamPriority::BULK,
            framing: LinkFraming::SelfDelimitingStream {
                peer_cid: match crate::wire::ConnectionId::new(1) {
                    Some(c) => c,
                    None => unreachable!(),
                },
            },
            congestion_mode: CongestionMode::FlowControlled {
                max_inflight_bytes,
                max_inflight_packets: 128,
            },
            initial_rtt_us: 10_000,
        }
    }

    /// Profile for a standard UDP datagram link with NewReno congestion control and pacing.
    pub const fn udp_datagram(tier: u8, mtu: usize, peer_cid: crate::wire::ConnectionId) -> Self {
        Self {
            tier,
            mtu,
            max_priority: StreamPriority::BULK,
            framing: LinkFraming::Datagram { peer_cid },
            congestion_mode: CongestionMode::NewRenoPaced {
                initial_window_bytes: 0,
                pacing: PacingConfig::host(mtu),
            },
            initial_rtt_us: 25_000,
        }
    }

    /// Profile for a low-rate / long-range radio link (LoRa or multicast ESP-NOW without MAC ACK).
    ///
    /// By default, admits only `CRITICAL`, `HIGH`, and `NORMAL` short messaging streams and
    /// high-priority datagrams (`max_priority = StreamPriority::NORMAL`), rejecting `LOW` and `BULK`.
    pub const fn radio_short_messages(
        tier: u8,
        mtu: usize,
        peer_cid: crate::wire::ConnectionId,
        max_inflight_packets: usize,
        min_interval_us: u64,
        min_pto_us: u64,
    ) -> Self {
        Self {
            tier,
            mtu,
            max_priority: StreamPriority::NORMAL,
            framing: LinkFraming::Datagram { peer_cid },
            congestion_mode: CongestionMode::Radio {
                max_inflight_packets,
                max_driver_queue_packets: 2,
                min_interval_us,
                min_pto_us,
            },
            initial_rtt_us: min_pto_us / 2,
        }
    }
}

/// RFC 9002 RTT estimator (ported from `quic-lite::RttEstimator`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RttEstimator {
    latest_rtt: Option<u64>,
    smoothed_rtt: Option<u64>,
    rttvar: u64,
    min_rtt: Option<u64>,
    min_rtt_sampled_at_us: Option<u64>,
    minimum_age_window_us: u64,
    initial_pto_us: u64,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new(250_000)
    }
}

impl RttEstimator {
    const GRANULARITY_US: u64 = 1_000;

    /// Create an `RttEstimator` with the given `initial_pto_us` before any ACK sample is observed.
    pub const fn new(initial_pto_us: u64) -> Self {
        Self {
            latest_rtt: None,
            smoothed_rtt: None,
            rttvar: 0,
            min_rtt: None,
            min_rtt_sampled_at_us: None,
            minimum_age_window_us: 60_000_000,
            initial_pto_us: if initial_pto_us < Self::GRANULARITY_US {
                Self::GRANULARITY_US
            } else {
                initial_pto_us
            },
        }
    }

    /// Record a new RTT sample `sample_us` at monotonic timestamp `now_us`.
    pub fn update_at(&mut self, sample_us: u64, now_us: u64) {
        let sample = sample_us.max(1);
        self.latest_rtt = Some(sample);
        let minimum_expired = self.min_rtt_sampled_at_us.is_none_or(|sampled_at| {
            now_us.saturating_sub(sampled_at) >= self.minimum_age_window_us
        });
        if minimum_expired || self.min_rtt.is_none_or(|minimum| sample < minimum) {
            self.min_rtt = Some(sample);
            self.min_rtt_sampled_at_us = Some(now_us);
        }
        match self.smoothed_rtt {
            None => {
                self.smoothed_rtt = Some(sample);
                self.rttvar = sample / 2;
            }
            Some(smoothed) => {
                let variation = smoothed.abs_diff(sample);
                self.rttvar = (self.rttvar.saturating_mul(3).saturating_add(variation)) / 4;
                self.smoothed_rtt = Some(smoothed.saturating_mul(7).saturating_add(sample) / 8);
            }
        }
    }

    /// Most recent RTT sample in microseconds.
    #[inline]
    pub const fn latest(&self) -> Option<u64> {
        self.latest_rtt
    }

    /// Smoothed RTT in microseconds.
    #[inline]
    pub const fn smoothed(&self) -> Option<u64> {
        self.smoothed_rtt
    }

    /// RTT variation in microseconds.
    #[inline]
    pub const fn variance(&self) -> u64 {
        self.rttvar
    }

    /// Minimum observed RTT in microseconds.
    #[inline]
    pub const fn minimum(&self) -> Option<u64> {
        self.min_rtt
    }

    /// Base Probe Timeout (PTO) in microseconds (`smoothed_rtt + max(4 * rttvar, 1ms)`).
    #[inline]
    pub fn pto(&self) -> u64 {
        let Some(smoothed) = self.smoothed_rtt else {
            return self.initial_pto_us;
        };
        smoothed
            .saturating_add(self.rttvar.saturating_mul(4).max(Self::GRANULARITY_US))
            .max(Self::GRANULARITY_US)
    }
}

/// RFC 9002 NewReno congestion controller (ported from `quic-lite::CongestionController`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CongestionController {
    /// Maximum datagram size (`MTU`) in bytes.
    pub max_packet_size: u64,
    /// Current congestion window in bytes.
    pub congestion_window: u64,
    /// Slow-start threshold in bytes (`u64::MAX` while in slow start).
    pub slow_start_threshold: u64,
    /// Unacknowledged bytes currently in flight on this link.
    pub bytes_in_flight: u64,
    /// Largest packet number sent when the current NewReno recovery epoch started.
    recovery_start_packet: Option<u32>,
}

impl CongestionController {
    /// Construct a NewReno controller with `max_packet_size` and optional `initial_window_bytes`.
    pub fn new(max_packet_size: u64, initial_window_bytes: u64) -> Self {
        let mds = max_packet_size.max(1);
        let default_init = (10 * mds).min((2 * mds).max(14_720));
        let initial_window = if initial_window_bytes == 0 {
            default_init
        } else {
            initial_window_bytes.max(2 * mds)
        };
        Self {
            max_packet_size: mds,
            congestion_window: initial_window,
            slow_start_threshold: u64::MAX,
            bytes_in_flight: 0,
            recovery_start_packet: None,
        }
    }

    /// Whether `bytes` can be admitted within `congestion_window`.
    #[inline]
    pub const fn can_send(&self, bytes: u64) -> bool {
        self.bytes_in_flight.saturating_add(bytes) <= self.congestion_window
    }

    /// Record a transmitted packet of `bytes` size.
    pub fn on_packet_sent(&mut self, bytes: u64) -> bool {
        if !self.can_send(bytes) {
            return false;
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
        true
    }

    /// Record a PTO probe packet (allowed even when `bytes_in_flight >= congestion_window`).
    pub fn on_pto_probe_sent(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
    }

    /// Process newly acknowledged bytes (`allow_growth` is true when the packet was sent while
    /// window-limited or in slow start).
    pub fn on_ack(&mut self, acked_bytes: u64, allow_growth: bool) {
        let acked = min(acked_bytes, self.bytes_in_flight);
        self.bytes_in_flight -= acked;
        if acked == 0 || !allow_growth {
            return;
        }
        if self.congestion_window < self.slow_start_threshold {
            self.congestion_window = self.congestion_window.saturating_add(acked);
        } else {
            let increase =
                (self.max_packet_size.saturating_mul(acked) / self.congestion_window.max(1)).max(1);
            self.congestion_window = self.congestion_window.saturating_add(increase);
        }
    }

    /// Remove `bytes` from flight without declaring network congestion (e.g. local bearer `Failed`
    /// before transmission or link suspension).
    pub fn remove_in_flight(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
    }

    /// Account a transport-declared packet loss using NewReno recovery epochs.
    pub fn on_packet_lost(
        &mut self,
        lost_bytes: u64,
        lost_packet_number: u32,
        largest_sent_packet: u32,
    ) {
        if lost_bytes == 0 {
            return;
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        if self
            .recovery_start_packet
            .is_some_and(|start| lost_packet_number <= start)
        {
            return;
        }
        let reduced = self.congestion_window / 2;
        self.slow_start_threshold = reduced.max(2 * self.max_packet_size);
        self.congestion_window = self.slow_start_threshold;
        self.recovery_start_packet = Some(largest_sent_packet);
    }

    /// Collapse congestion window to `2 * max_packet_size` upon persistent congestion.
    pub fn on_persistent_congestion(&mut self, largest_sent_packet: u32) {
        self.congestion_window = 2 * self.max_packet_size;
        self.recovery_start_packet = Some(largest_sent_packet);
    }
}

fn pacing_refill_tokens(elapsed: u64, window: u64, rtt: u64, mss: u64) -> (u64, u64) {
    let rtt = rtt.max(1);
    let mss = mss.max(1);
    if let Some(numerator) = elapsed
        .checked_mul(window)
        .and_then(|n| n.checked_mul(1 << 16))
    {
        let bytes = numerator / rtt;
        return (bytes, bytes / mss);
    }
    let bytes = u128::from(elapsed)
        .saturating_mul(u128::from(window))
        .saturating_mul(1 << 16)
        / u128::from(rtt);
    (
        bytes.min(u128::from(u64::MAX)) as u64,
        (bytes / u128::from(mss)).min(u128::from(u64::MAX)) as u64,
    )
}

fn pacing_wait_us(deficit: u64, scale: u128, denominator: u128) -> u64 {
    let denominator = denominator.max(1);
    if deficit == 0 {
        return 0;
    }
    if let (Ok(scale), Ok(divisor)) = (u64::try_from(scale), u64::try_from(denominator)) {
        if let Some(numerator) = deficit
            .checked_mul(scale)
            .and_then(|value| value.checked_add(divisor - 1))
        {
            return numerator / divisor;
        }
    }
    (u128::from(deficit)
        .saturating_mul(scale)
        .saturating_add(denominator - 1)
        / denominator)
        .min(u128::from(u64::MAX)) as u64
}

/// Per-link runtime state combining RTT estimation, congestion/flight accounting, pacing,
/// per-link send-order counter, and failure/backoff tracking.
#[derive(Clone, Debug)]
pub struct LinkState {
    /// Identifier of this link.
    pub id: LinkId,
    /// Configured profile for this link.
    pub profile: LinkProfile,
    /// Whether this link is currently enabled/up.
    pub enabled: bool,
    /// Whether the physical driver reported it can accept a packet now.
    pub driver_ready: bool,
    /// Packets currently handed to the physical driver awaiting `LinkTxOutcome` completion.
    pub driver_in_flight: usize,
    /// Unacknowledged packets in flight on this link awaiting peer SACK.
    pub packets_in_flight: usize,
    /// Per-link RTT estimator.
    pub rtt: RttEstimator,
    /// NewReno congestion controller (used by `NewRenoPaced` and tracks `bytes_in_flight` for all modes).
    pub congestion: CongestionController,
    /// Monotonically increasing send order on this specific link (used for per-link SACK reordering detection).
    pub next_send_order: u64,
    /// Largest `send_order` acknowledged by the peer on this link.
    pub largest_acked_send_order: Option<u64>,
    /// Largest packet number sent on this link.
    pub largest_sent_packet: Option<u32>,
    /// Largest packet number acknowledged on this link.
    pub largest_acked_packet: Option<u32>,
    /// Adaptive packet reordering threshold on this link (starts at 3, adapts on spurious loss).
    pub packet_reordering_threshold: u64,
    /// Adaptive time-threshold loss ratio in Q16 (`9/8 = 73,728` initially).
    pub loss_time_ratio_q16: u64,
    /// Timestamp of the last transmission on this link.
    pub last_tx_at_us: Option<u64>,
    /// Exponential PTO backoff exponent (`0..=3`).
    pub pto_backoff: u8,
    /// Timestamp of the last PTO probe sent on this link.
    pub last_pto_probe_at_us: Option<u64>,
    /// Q16 byte tokens for `NewRenoPaced`.
    pacing_byte_tokens_q16: u64,
    /// Q16 packet tokens for `NewRenoPaced`.
    pacing_packet_tokens_q16: u64,
    /// Last token-bucket refill timestamp.
    pacing_last_refill_us: u64,
    /// Next pacing wake deadline if blocked on pacing tokens or radio airtime interval.
    pacing_deadline_us: Option<u64>,
    /// Telemetry counters for this link.
    pub stats: LinkStats,
}

/// Per-link diagnostic counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkStats {
    /// Total packets transmitted on this link.
    pub packets_sent: u64,
    /// Total wire bytes transmitted on this link.
    pub bytes_sent: u64,
    /// Total packets acknowledged from this link.
    pub packets_acked: u64,
    /// Total packets declared lost on this link (by SACK gap or time threshold).
    pub packets_lost: u64,
    /// Late ACKs received for packets previously declared lost on this link.
    pub spurious_losses: u64,
    /// Retransmissions sent over this link (including failover repairs from other links).
    pub retransmissions_sent: u64,
    /// Unreliable `DATAGRAM` frames transmitted on this link.
    pub datagrams_sent: u64,
    /// Physical driver `Failed` completions.
    pub driver_failures: u64,
}

impl LinkState {
    /// Create a new `LinkState` from `id` and `profile`.
    pub fn new(id: LinkId, profile: LinkProfile) -> Self {
        let initial_window = match profile.congestion_mode {
            CongestionMode::FlowControlled {
                max_inflight_bytes, ..
            } => max_inflight_bytes,
            CongestionMode::NewRenoPaced {
                initial_window_bytes,
                ..
            } => initial_window_bytes,
            CongestionMode::Radio {
                max_inflight_packets,
                ..
            } => (max_inflight_packets * profile.mtu) as u64,
        };
        let (burst_bytes, burst_pkts) = match profile.congestion_mode {
            CongestionMode::NewRenoPaced { pacing, .. } => (
                u64::from(pacing.max_burst_bytes) << 16,
                u64::from(pacing.max_burst_packets) << 16,
            ),
            _ => (0, 0),
        };
        let initial_pto = match profile.congestion_mode {
            CongestionMode::Radio { min_pto_us, .. } => min_pto_us.max(profile.initial_rtt_us * 2),
            _ => (profile.initial_rtt_us * 2).max(50_000),
        };
        Self {
            id,
            profile,
            enabled: true,
            driver_ready: true,
            driver_in_flight: 0,
            packets_in_flight: 0,
            rtt: RttEstimator::new(initial_pto),
            congestion: CongestionController::new(profile.mtu as u64, initial_window),
            next_send_order: 1,
            largest_acked_send_order: None,
            largest_sent_packet: None,
            largest_acked_packet: None,
            packet_reordering_threshold: 3,
            loss_time_ratio_q16: 9 * (1 << 16) / 8,
            last_tx_at_us: None,
            pto_backoff: 0,
            last_pto_probe_at_us: None,
            pacing_byte_tokens_q16: burst_bytes,
            pacing_packet_tokens_q16: burst_pkts,
            pacing_last_refill_us: 0,
            pacing_deadline_us: None,
            stats: LinkStats::default(),
        }
    }

    /// Effective PTO timeout in microseconds for this link (including radio `min_pto_us` floor and backoff).
    pub fn pto_timeout_us(&self, max_ack_delay_us: u64) -> u64 {
        let base = self.rtt.pto().saturating_add(max_ack_delay_us);
        let floored = match self.profile.congestion_mode {
            CongestionMode::Radio { min_pto_us, .. } => base.max(min_pto_us),
            _ => base,
        };
        floored.saturating_mul(1u64 << self.pto_backoff.min(3))
    }

    /// Time-threshold loss delay in microseconds (`9/8 * max(latest_rtt, smoothed_rtt) + max_ack_delay_us`).
    pub fn loss_delay_us(&self, max_ack_delay_us: u64) -> u64 {
        let base_rtt = self
            .rtt
            .latest()
            .unwrap_or(self.profile.initial_rtt_us)
            .max(self.rtt.smoothed().unwrap_or(self.profile.initial_rtt_us))
            .max(1);
        let delay = base_rtt
            .saturating_mul(self.loss_time_ratio_q16)
            .div_ceil(1 << 16)
            .saturating_add(max_ack_delay_us);
        match self.profile.congestion_mode {
            CongestionMode::Radio { min_pto_us, .. } => delay.max(min_pto_us),
            _ => delay,
        }
    }

    /// Next pacing or airtime deadline if this link is currently rate-limited.
    #[inline]
    pub const fn pacing_deadline_us(&self) -> Option<u64> {
        self.pacing_deadline_us
    }

    /// Estimated one-way arrival time in microseconds for a new packet of `packet_bytes` on this link.
    ///
    /// Combines smoothed one-way delay (`rtt / 2`), any remaining airtime/pacing wait, and the
    /// serialization drain time of currently in-flight bytes (`bytes_in_flight * rtt / cwnd`).
    pub fn estimated_arrival_delay_us(&self, now_us: u64) -> u64 {
        let rtt = self
            .rtt
            .smoothed()
            .unwrap_or(self.profile.initial_rtt_us)
            .max(100);
        let one_way = rtt / 2;
        let pace_wait = self
            .pacing_deadline_us
            .map_or(0, |d| d.saturating_sub(now_us));
        let queue_delay = (self.congestion.bytes_in_flight.saturating_mul(rtt))
            / self.congestion.congestion_window.max(1);
        one_way
            .saturating_add(pace_wait)
            .saturating_add(queue_delay)
    }

    /// Check whether this link can admit a packet of `packet_bytes` with `priority` at `now_us`
    /// (`is_pto_probe` allows bypassing congestion window for a single recovery probe).
    pub fn can_admit(
        &mut self,
        packet_bytes: usize,
        priority: StreamPriority,
        now_us: u64,
        is_pto_probe: bool,
    ) -> bool {
        if !self.enabled || !self.driver_ready || packet_bytes > self.profile.mtu {
            return false;
        }
        // Enforce link priority filter (e.g., block LOW/BULK from LoRa/ESP-NOW).
        if priority.is_lower_than(self.profile.max_priority) {
            return false;
        }
        let bytes = packet_bytes as u64;
        match self.profile.congestion_mode {
            CongestionMode::FlowControlled {
                max_inflight_bytes,
                max_inflight_packets,
            } => {
                self.pacing_deadline_us = None;
                if is_pto_probe {
                    return true;
                }
                self.packets_in_flight < max_inflight_packets
                    && self.congestion.bytes_in_flight.saturating_add(bytes) <= max_inflight_bytes
            }
            CongestionMode::NewRenoPaced { pacing, .. } => {
                if !is_pto_probe && !self.congestion.can_send(bytes) {
                    return false;
                }
                self.check_and_refill_pacing(pacing, bytes, now_us)
            }
            CongestionMode::Radio {
                max_inflight_packets,
                max_driver_queue_packets,
                min_interval_us,
                ..
            } => {
                if self.driver_in_flight >= max_driver_queue_packets {
                    return false;
                }
                if !is_pto_probe && self.packets_in_flight >= max_inflight_packets {
                    return false;
                }
                if min_interval_us > 0 {
                    if let Some(last_tx) = self.last_tx_at_us {
                        let next_allowed = last_tx.saturating_add(min_interval_us);
                        if now_us < next_allowed {
                            self.pacing_deadline_us = Some(next_allowed);
                            return false;
                        }
                    }
                }
                self.pacing_deadline_us = None;
                true
            }
        }
    }

    /// Commit a packet transmission on this link, returning `(link_send_order, window_limited)`.
    pub fn record_packet_sent(
        &mut self,
        packet_number: u32,
        packet_bytes: usize,
        now_us: u64,
        ack_eliciting: bool,
        is_pto_probe: bool,
    ) -> (u64, bool) {
        let bytes = packet_bytes as u64;
        let window_limited = self
            .congestion
            .bytes_in_flight
            .saturating_add(bytes)
            .saturating_add(self.congestion.max_packet_size)
            >= self.congestion.congestion_window;

        if let CongestionMode::NewRenoPaced { pacing, .. } = self.profile.congestion_mode {
            if pacing.enabled {
                let _ = self.check_and_refill_pacing(pacing, bytes, now_us);
                self.pacing_byte_tokens_q16 = self
                    .pacing_byte_tokens_q16
                    .saturating_sub(bytes.saturating_mul(1 << 16));
                self.pacing_packet_tokens_q16 =
                    self.pacing_packet_tokens_q16.saturating_sub(1 << 16);
            }
        }

        if ack_eliciting {
            if is_pto_probe {
                self.congestion.on_pto_probe_sent(bytes);
                self.last_pto_probe_at_us = Some(now_us);
            } else {
                self.congestion.bytes_in_flight =
                    self.congestion.bytes_in_flight.saturating_add(bytes);
            }
            self.packets_in_flight += 1;
        }

        self.driver_in_flight += 1;
        self.last_tx_at_us = Some(now_us);
        self.largest_sent_packet = Some(
            self.largest_sent_packet
                .map_or(packet_number, |prev| prev.max(packet_number)),
        );
        let send_order = self.next_send_order;
        self.next_send_order = self.next_send_order.saturating_add(1);
        self.stats.packets_sent += 1;
        self.stats.bytes_sent += bytes;
        (send_order, window_limited)
    }

    /// Record physical driver completion (`Sent`, `Failed`, or `Indeterminate`).
    pub fn on_driver_complete(&mut self, outcome: LinkTxOutcome) {
        self.driver_in_flight = self.driver_in_flight.saturating_sub(1);
        if outcome == LinkTxOutcome::Failed {
            self.stats.driver_failures += 1;
        }
    }

    /// Adapt reordering threshold and time-loss ratio when a packet previously declared lost on
    /// this link is later acknowledged by the peer.
    pub fn on_spurious_loss_ack(&mut self, send_order: u64, sent_at_us: u64, now_us: u64) {
        self.stats.spurious_losses += 1;
        let distance = self
            .largest_acked_send_order
            .unwrap_or(send_order)
            .saturating_sub(send_order)
            .saturating_add(1);
        self.packet_reordering_threshold = self.packet_reordering_threshold.max(distance.min(128));
        let base_rtt = self
            .rtt
            .latest()
            .unwrap_or(self.profile.initial_rtt_us)
            .max(self.rtt.smoothed().unwrap_or(self.profile.initial_rtt_us))
            .max(1);
        let elapsed = now_us.saturating_sub(sent_at_us);
        let ratio = elapsed
            .saturating_mul(9 * (1 << 16))
            .div_ceil(base_rtt.saturating_mul(8));
        self.loss_time_ratio_q16 = self.loss_time_ratio_q16.max(ratio.min(4 * (1 << 16)));
    }

    fn check_and_refill_pacing(
        &mut self,
        pacing: PacingConfig,
        packet_bytes: u64,
        now_us: u64,
    ) -> bool {
        if !pacing.enabled {
            self.pacing_deadline_us = None;
            return true;
        }
        const Q16: u128 = 1 << 16;
        let window = u128::from(self.congestion.congestion_window.max(1));
        let rtt = u128::from(
            self.rtt
                .smoothed()
                .unwrap_or(self.profile.initial_rtt_us)
                .max(1),
        );
        let mss = u128::from(self.congestion.max_packet_size.max(1));
        let elapsed = now_us.saturating_sub(self.pacing_last_refill_us);
        if elapsed != 0 {
            let byte_cap = u64::from(pacing.max_burst_bytes) << 16;
            let packet_cap = u64::from(pacing.max_burst_packets) << 16;
            let (byte_refill, packet_refill) =
                pacing_refill_tokens(elapsed, window as u64, rtt as u64, mss as u64);
            self.pacing_byte_tokens_q16 = self
                .pacing_byte_tokens_q16
                .saturating_add(byte_refill)
                .min(byte_cap);
            self.pacing_packet_tokens_q16 = self
                .pacing_packet_tokens_q16
                .saturating_add(packet_refill)
                .min(packet_cap);
            self.pacing_last_refill_us = now_us;
        }
        let needed_bytes = packet_bytes.saturating_mul(1 << 16);
        let needed_packet = 1u64 << 16;
        let byte_deficit = needed_bytes.saturating_sub(self.pacing_byte_tokens_q16);
        let packet_deficit = needed_packet.saturating_sub(self.pacing_packet_tokens_q16);
        if byte_deficit != 0 || packet_deficit != 0 {
            let byte_denominator = window.saturating_mul(Q16).max(1);
            let byte_wait = pacing_wait_us(byte_deficit, rtt, byte_denominator);
            let packet_denominator = rtt.saturating_mul(mss).max(1);
            let packet_wait = if packet_deficit == 0 {
                0
            } else {
                pacing_wait_us(packet_deficit, packet_denominator, byte_denominator)
            };
            self.pacing_deadline_us =
                Some(now_us.saturating_add(byte_wait.max(packet_wait).max(1)));
            return false;
        }
        self.pacing_deadline_us = None;
        true
    }
}
