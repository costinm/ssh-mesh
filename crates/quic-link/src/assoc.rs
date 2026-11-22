//! Multi-link QUIC association manager (`QuicLinkAssoc`), `AssociationEgress<P>` implementation
//! for `QuicMux`, and standalone single-stream UDP/radio endpoint (`SingleStreamEndpoint`).

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::cmp::min;
use core::ops::Range;

use quic_base::flow::{RecvFlowControl, RxOutcome, SendFlowControl};
use quic_base::initial::{
    DMESH_QUIC_VERSION, FRAME_CRYPTO, InitialHeader, TransportParameters, decode_crypto_frame_body,
    encode_crypto_frame, is_initial_packet,
};
use quic_base::link::{default_coalesce_threshold, try_coalesce_tx_packet};
use quic_base::pool::{PacketPool, PoolError, PoolPacket};
use quic_base::streams::{OrderedStream, QueuedPayload, RxStreamChunk, TxStreamData};
use quic_base::wire::{
    Frame, StreamId, WireError, decode_frame, decode_varint, encode_control_frame,
    encode_stream_header, varint_len,
};
use quic_base::{
    AEAD_TAG_LEN, ASSOCIATION_RANDOM_LEN, AssociationEgress, AssociationId, CryptoError,
    CryptoProvider, CryptoRole, EndpointKeys, FLAG_PROTECTED, LinkSendError, OWNER_ASSOC,
    PUBLIC_KEY_COMPRESSED_LEN, StreamPriority, TxPacketMeta, compute_initial_verifier_with,
    derive_peer_api_key_with, derive_static_traffic_keys_with, derive_traffic_keys_with,
    open_short_packet_in_place, seal_short_packet_in_place_with_pn, verify_initial_verifier_with,
};

use crate::LinkMap;
use crate::congestion::{LinkFraming, LinkId, LinkProfile, LinkState, LinkTxOutcome};
use crate::datagram::{DatagramConfig, DatagramSendError, prepend_datagram_frame_in_place};
use crate::reset::StatelessResetToken;
use crate::sack::{AckProcessOutcome, LinkRetransmitCandidate, MultiLinkSackLedger};
use crate::wire::{
    AckFrequencyFrame, AckRangeSet, ConnectionId, FRAME_ACK, FRAME_ACK_FREQUENCY, FRAME_DATAGRAM,
    FRAME_DATAGRAM_LEN, FRAME_PADDING, FRAME_PING, ShortHeader, decode_ack_frame_body,
    encode_ack_frame, packet_number_len,
};

/// Framed outbound wire packet queued for physical transmission on a specific [`LinkId`].
#[derive(Debug)]
pub struct OutboundLinkPacket<P: PoolPacket> {
    /// Selected link identifier.
    pub link_id: LinkId,
    /// Assigned association-wide packet number (`>= 1` for `ShortHeader` packets).
    pub packet_number: u32,
    /// Metadata for the packet.
    pub meta: TxPacketMeta,
    /// Byte range of the inner `quic-mux` / `DATAGRAM` frames (prior to prepending piggybacked
    /// `ACK` and `ShortHeader`), used when coalescing small subsequent packets onto this packet
    /// before the physical driver dequeues it.
    pub inner_frame_range: Range<usize>,
    /// Whether this packet already carries a piggybacked `ACK` frame.
    pub carries_ack: bool,
    /// Whether this packet elicits a peer `ACK`.
    pub ack_eliciting: bool,
    /// Framed `PoolPacket` ready for transmission on `link_id` (`packet.bytes()` begins at the
    /// `ShortHeader`).
    pub packet: P,
}

/// Initial handshake operating mode for a [`QuicLinkAssoc`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HandshakeMode {
    /// Legacy or pre-keyed direct `ShortHeader` mode (no RFC 9000 `Initial` exchange).
    #[default]
    None,
    /// Client role: emits RFC 9000 `Initial` + `CRYPTO` (`TransportParameters`) packets until
    /// receiving Server `Initial`, adopting the server's `scid` as peer DCID.
    Client,
    /// Server role: accepts Client `Initial`, adopts client `scid`, emits Server `Initial`, and
    /// transitions to `ShortHeader` once confirmed.
    Server,
}

/// Phase A per-association authentication and per-link `ShortHeader` encryption configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssocCryptoConfig {
    /// Cryptographic backend provider (`CryptoProvider::rust_crypto()` on Linux/Android, or native
    /// PSA Crypto via `xip_abi::CryptoClient` on ESP32 modules).
    pub provider: CryptoProvider,
    /// Endpoint role (`CryptoRole::Client` or `CryptoRole::Server`) for key directionality.
    pub role: CryptoRole,
    /// Local 33-byte compressed SEC1 P-256 public key advertised in `Initial` (`TP_DMESH_PUBLIC_KEY`).
    pub local_public_key: Option<[u8; PUBLIC_KEY_COMPRESSED_LEN]>,
    /// Local 32-byte per-association random nonce advertised in `Initial` (`TP_DMESH_RANDOM`).
    pub local_random: [u8; ASSOCIATION_RANDOM_LEN],
    /// Pre-shared / provisioned 32-byte per-peer `api_key` (required on `Client` and on pre-keyed
    /// `HandshakeMode::None` associations; optional on `Server` when `node_secret` is configured).
    pub send_api_key: Option<[u8; 32]>,
    /// Node's single 32-byte secret used to derive per-caller `api_key`s from an incoming peer
    /// `public_key` (`derive_peer_api_key_with(&provider, node_secret, caller_public_key)`).
    pub node_secret: Option<[u8; 32]>,
}

/// Configuration for a [`QuicLinkAssoc`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssocConfig {
    /// Association identifier (`OWNER_ASSOC` by default).
    pub assoc_id: AssociationId,
    /// Local connection identifier expected on incoming packets (`None` accepts any CID).
    pub local_cid: Option<ConnectionId>,
    /// Default peer destination connection identifier.
    pub default_peer_cid: ConnectionId,
    /// Initial limit on retained unacknowledged TX packets in [`MultiLinkSackLedger`].
    pub max_retained_tx_packets: usize,
    /// Number of ack-eliciting packets received before sending an immediate `ACK` (`2` by default).
    pub ack_eliciting_threshold: u32,
    /// Maximum ACK delay in microseconds (`25_000` = 25 ms by default).
    pub max_ack_delay_us: u64,
    /// Unreliable `DATAGRAM` (`0x30` / `0x31`) configuration.
    pub datagram: DatagramConfig,
    /// RFC 9000 `Initial` handshake role (`HandshakeMode::None` by default for backwards compatibility).
    pub handshake_mode: HandshakeMode,
    /// Transport parameters advertised inside outgoing `Initial` `CRYPTO` (`0x06`) frames.
    pub local_params: TransportParameters,
    /// Optional DCID placed in Client `Initial` Long Headers (`None` for 1-hop direct, or
    /// `Some(relay_cid)` when routed through a relay hop).
    pub initial_dcid: Option<ConnectionId>,
}

impl Default for AssocConfig {
    fn default() -> Self {
        Self {
            assoc_id: OWNER_ASSOC,
            local_cid: ConnectionId::new(1),
            default_peer_cid: ConnectionId::new(1).unwrap(),
            max_retained_tx_packets: 64,
            ack_eliciting_threshold: 2,
            max_ack_delay_us: 25_000,
            datagram: DatagramConfig::default(),
            handshake_mode: HandshakeMode::None,
            local_params: TransportParameters::default(),
            initial_dcid: None,
        }
    }
}

/// Result of receiving and demultiplexing one incoming wire packet in [`QuicLinkAssoc::receive_packet`].
#[derive(Debug)]
pub struct DemuxOutcome<P: PoolPacket> {
    /// Reconstructed 32-bit packet number of the received packet.
    pub packet_number: u32,
    /// Link on which the packet arrived.
    pub link_id: LinkId,
    /// Whether the received packet carried an RFC 9000 `Initial` Long Header.
    pub is_initial: bool,
    /// Source CID parsed from an incoming `Initial` Long Header, if present.
    pub peer_scid: Option<ConnectionId>,
    /// Peer transport parameters decoded from a `CRYPTO` (`0x06`) frame in this packet, if any.
    pub peer_params: Option<TransportParameters>,
    /// Whether the packet contained any `ACK` frame.
    pub had_ack: bool,
    /// Number of newly acknowledged TX packets if an `ACK` frame was processed.
    pub newly_acked_packets: usize,
    /// Number of TX packets queued for retransmission by an incoming `ACK` frame.
    pub retransmits_queued: usize,
    /// Zero-copy unreliable `DATAGRAM` payloads extracted from this packet.
    pub datagrams: Vec<P>,
    /// Remaining `PoolPacket` positioned at the start of inner `quic-mux` (`STREAM` / control)
    /// frames, ready to pass to `QuicMux::receive_packet` or [`SingleStreamEndpoint`].
    pub mux_packet: Option<P>,
}

/// Errors during [`QuicLinkAssoc::receive_packet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkRecvError {
    /// Wire header or frame was malformed.
    Wire(WireError),
    /// Destination CID did not match `local_cid`.
    UnknownConnectionId(ConnectionId),
    /// Duplicate packet number (already recorded in `rx_ack_ranges`).
    DuplicatePacket(u32),
    /// Incoming `DATAGRAM` exceeded `max_recv_datagram_size`.
    DatagramTooLarge(usize),
    /// Handshake `Initial` verifier check or `ShortHeader` AEAD decryption/authentication failed.
    Crypto(CryptoError),
}

/// Multi-link QUIC association manager sitting below `QuicMux` (via [`AssociationEgress`]) or
/// driving [`SingleStreamEndpoint`] directly without `QuicMux`.
///
/// Responsibilities:
/// - Manages multiple heterogeneous [`LinkState`]s (UDP, TCP/UDS/PPP streams, LoRa, ESP-NOW, NAN).
/// - Selects outgoing links using priority eligibility (`priority <= link.profile.max_priority`),
///   per-stream link affinity, cost tier, and lowest `estimated_arrival_delay_us`.
/// - Assigns association-wide packet numbers, piggybacks pending `ACK` frames into packet
///   headroom (`< 112` bytes) whenever space permits, and prepends `ShortHeader` in-place.
/// - Performs small-packet coalescing (`<= 1/3 MTU`) onto pending outbound packets for the same
///   link.
/// - Tracks unacknowledged packets in [`MultiLinkSackLedger`] with per-link `send_order` SACK
///   loss detection, PTO recovery, link-failure evacuation, and priority-based stream eviction.
pub struct QuicLinkAssoc<P: PoolPacket> {
    config: AssocConfig,
    now_us: u64,
    next_pkt_num: u32,
    expected_rx_pkt_num: u32,
    links: LinkMap<LinkId, LinkState>,
    stream_affinity: LinkMap<StreamId, LinkId>,
    sack_ledger: MultiLinkSackLedger<P>,
    rx_ack_ranges: AckRangeSet,
    last_rx_pkt_num: Option<u32>,
    rx_ack_eliciting_since_last_ack: u32,
    rx_immediate_ack_pending: bool,
    rx_ack_deadline_us: Option<u64>,
    rx_largest_received_at_us: Option<u64>,
    rx_reordering_threshold: u32,
    last_ack_freq_seq: Option<u64>,
    pending_retransmits: VecDeque<LinkRetransmitCandidate<P>>,
    outbound_queue: VecDeque<OutboundLinkPacket<P>>,
    evicted_streams: Vec<(AssociationId, StreamId)>,
    advisory_available_conn_window: u64,
    handshake_complete: bool,
    server_initial_needed: bool,
    server_initial_sent: bool,
    peer_scid: Option<ConnectionId>,
    peer_params: Option<TransportParameters>,
    crypto_config: Option<AssocCryptoConfig>,
    endpoint_keys: Option<EndpointKeys>,
    local_endpoint_dcid: ConnectionId,
    peer_endpoint_dcid: ConnectionId,
}

impl<P: PoolPacket> QuicLinkAssoc<P> {
    /// Worst-case outer `ShortHeader` byte overhead reserved on every packet (`1` flag + `8` CID + `4` PN = `13` bytes).
    pub const MAX_OUTER_HEADER_OVERHEAD: usize = ShortHeader::MAX_LEN;
    /// Outer overhead budget reserved when emitting RFC 9000 `InitialHeader + CRYPTO(TransportParameters)`
    /// packets (right-shifted into slot tailroom automatically when exceeding `DEFAULT_HEADROOM`).
    pub const MAX_INITIAL_OUTER_OVERHEAD: usize = 208;

    /// Create a new `QuicLinkAssoc` with `config`.
    pub fn new(config: AssocConfig) -> Self {
        let handshake_complete = matches!(config.handshake_mode, HandshakeMode::None);
        let local_endpoint_dcid = config.local_cid.unwrap_or_else(|| ConnectionId::new(1).unwrap());
        let peer_endpoint_dcid = config.default_peer_cid;
        Self {
            sack_ledger: MultiLinkSackLedger::new(config.max_retained_tx_packets),
            config,
            now_us: 0,
            next_pkt_num: 1,
            expected_rx_pkt_num: 1,
            links: LinkMap::new(),
            stream_affinity: LinkMap::new(),
            rx_ack_ranges: AckRangeSet::new(),
            last_rx_pkt_num: None,
            rx_ack_eliciting_since_last_ack: 0,
            rx_immediate_ack_pending: false,
            rx_ack_deadline_us: None,
            rx_largest_received_at_us: None,
            rx_reordering_threshold: 1,
            last_ack_freq_seq: None,
            pending_retransmits: VecDeque::new(),
            outbound_queue: VecDeque::new(),
            evicted_streams: Vec::new(),
            advisory_available_conn_window: u64::MAX,
            handshake_complete,
            server_initial_needed: false,
            server_initial_sent: false,
            peer_scid: None,
            peer_params: None,
            crypto_config: None,
            endpoint_keys: None,
            local_endpoint_dcid,
            peer_endpoint_dcid,
        }
    }

    /// Whether the RFC 9000 `Initial` handshake has completed (always `true` for `HandshakeMode::None`).
    #[inline]
    pub const fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    /// Peer source CID learned from an incoming `Initial` Long Header, if any.
    #[inline]
    pub const fn peer_scid(&self) -> Option<ConnectionId> {
        self.peer_scid
    }

    /// Peer `TransportParameters` received in an `Initial` `CRYPTO` (`0x06`) frame, if any.
    #[inline]
    pub const fn peer_params(&self) -> Option<&TransportParameters> {
        self.peer_params.as_ref()
    }

    /// Peer 16-byte ULA `vip6` derived directly from [`TransportParameters::public_key`] (`SHA-256`)
    /// using `provider`.
    #[inline]
    pub fn peer_vip6_with(&self, provider: &CryptoProvider) -> Option<[u8; 16]> {
        self.peer_params
            .and_then(|p| p.peer_vip6_with(provider))
    }

    /// Peer 16-byte ULA `vip6` derived directly from [`TransportParameters::public_key`] (`SHA-256`)
    /// using the configured `AssocCryptoConfig` / `EndpointKeys` provider (or `CryptoProvider::rust_crypto()`
    /// on hosts when `feature = "rust-crypto"` is enabled).
    #[inline]
    pub fn peer_vip6(&self) -> Option<[u8; 16]> {
        if let Some(ref cfg) = self.crypto_config {
            return self.peer_vip6_with(&cfg.provider);
        }
        if let Some(ref keys) = self.endpoint_keys {
            return self.peer_vip6_with(keys.send.provider());
        }
        #[cfg(feature = "rust-crypto")]
        {
            return self.peer_vip6_with(&CryptoProvider::rust_crypto());
        }
        #[cfg(not(feature = "rust-crypto"))]
        None
    }

    /// Whether `ShortHeader` AEAD encryption/authentication keys are currently installed.
    #[inline]
    pub const fn has_packet_crypto(&self) -> bool {
        self.endpoint_keys.is_some()
    }

    /// Directly install pre-derived directional `ShortHeader` [`EndpointKeys`] and canonical AAD CIDs.
    pub fn set_endpoint_keys(
        &mut self,
        keys: EndpointKeys,
        local_endpoint_dcid: ConnectionId,
        peer_endpoint_dcid: ConnectionId,
    ) {
        self.endpoint_keys = Some(keys);
        self.local_endpoint_dcid = local_endpoint_dcid;
        self.peer_endpoint_dcid = peer_endpoint_dcid;
    }

    /// Clear installed association crypto configuration and derived directional keys (returning to
    /// cleartext operation across all links).
    pub fn clear_crypto(&mut self) {
        self.crypto_config = None;
        self.endpoint_keys = None;
        self.config.local_params.verifier = None;
    }

    /// Configure Phase A `api_key` / `node_secret` authentication and per-link `ShortHeader` AEAD.
    ///
    /// Links whose [`LinkProfile::encrypt`] is `false` (such as PPP/UART/TCP or test-configured
    /// Wi-Fi/NOW links) remain unencrypted even when keys are installed.
    pub fn set_crypto_config(&mut self, cfg: AssocCryptoConfig) -> Result<(), CryptoError> {
        let local_dcid = self
            .config
            .local_cid
            .unwrap_or_else(|| ConnectionId::new(1).unwrap());
        let peer_dcid = self.peer_scid.unwrap_or(self.config.default_peer_cid);
        self.local_endpoint_dcid = local_dcid;
        self.peer_endpoint_dcid = peer_dcid;
        self.crypto_config = Some(cfg);
        self.config.local_params.public_key = cfg.local_public_key;
        self.config.local_params.random = Some(cfg.local_random);
        if self.config.local_params.initial_scid.is_none() {
            self.config.local_params.initial_scid = self.config.local_cid;
        }
        match self.config.handshake_mode {
            HandshakeMode::Client => {
                if self.config.initial_dcid.is_none() {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&cfg.local_random[..8]);
                    let raw = (u64::from_be_bytes(bytes) & ConnectionId::MAX_VALUE) | 0x2000_0000;
                    self.config.initial_dcid = ConnectionId::new(raw);
                }
                if let (Some(api_key), Some(pub_key)) = (cfg.send_api_key, cfg.local_public_key) {
                    self.config.local_params.verifier = Some(compute_initial_verifier_with(
                        &cfg.provider,
                        &api_key,
                        CryptoRole::Client,
                        self.config.local_cid.or(self.config.local_params.initial_scid),
                        self.config.initial_dcid,
                        &pub_key,
                        &cfg.local_random,
                    )?);
                }
            }
            HandshakeMode::Server => {}
            HandshakeMode::None => {
                let api_key = match (cfg.send_api_key, cfg.node_secret) {
                    (Some(k), _) => k,
                    (None, Some(secret)) => derive_peer_api_key_with(&cfg.provider, &secret, &[])?,
                    (None, None) => return Err(CryptoError::Invalid),
                };
                let (client_cid, server_cid) = match cfg.role {
                    CryptoRole::Client => (local_dcid, peer_dcid),
                    CryptoRole::Server => (peer_dcid, local_dcid),
                };
                let keys = derive_static_traffic_keys_with(
                    &cfg.provider,
                    &api_key,
                    client_cid,
                    server_cid,
                )?
                .for_role(cfg.role);
                self.endpoint_keys = Some(keys);
            }
        }
        Ok(())
    }

    /// Peer 16-byte stateless reset token advertised inside [`TransportParameters::stateless_reset_token`].
    #[inline]
    pub fn peer_stateless_reset_token(&self) -> Option<StatelessResetToken> {
        self.peer_params
            .and_then(|p| p.stateless_reset_token)
            .map(StatelessResetToken::new)
    }

    /// Configured local connection identifier expected on incoming packets, if any.
    #[inline]
    pub const fn local_cid(&self) -> Option<ConnectionId> {
        self.config.local_cid
    }

    /// Update `default_peer_cid` and every attached link's destination `peer_cid` uniformly.
    pub fn set_peer_cid_all_links(&mut self, cid: ConnectionId) {
        self.config.default_peer_cid = cid;
        for (_, link) in &mut self.links {
            match &mut link.profile.framing {
                LinkFraming::Datagram { peer_cid }
                | LinkFraming::SelfDelimitingStream { peer_cid }
                | LinkFraming::TlsRecord { peer_cid } => {
                    *peer_cid = cid;
                }
            }
        }
    }

    /// Enqueue a standalone retransmittable `Initial + CRYPTO + PING` packet when a client wants to
    /// drive the handshake explicitly before opening a `STREAM`.
    pub fn enqueue_initial<Pool: PacketPool<Packet = P>>(
        &mut self,
        pool: &mut Pool,
    ) -> Result<(), PoolError> {
        let mut pkt = pool.alloc()?;
        pkt.append(&[FRAME_PING as u8])?;
        let meta = TxPacketMeta {
            association: self.config.assoc_id,
            stream_id: None,
            priority: StreamPriority::CRITICAL,
            retransmittable: true,
        };
        let _ = self.send_packet(meta, pkt);
        Ok(())
    }

    /// Current monotonic clock timestamp in microseconds.
    #[inline]
    pub const fn now_us(&self) -> u64 {
        self.now_us
    }

    /// Update the monotonic clock timestamp in microseconds.
    #[inline]
    pub fn set_now_us(&mut self, now_us: u64) {
        self.now_us = now_us;
    }

    /// Update the advisory connection-level send window (used to shed `LOW`/`BULK` datagrams when
    /// reliable streams are window-constrained).
    #[inline]
    pub fn set_advisory_available_conn_window(&mut self, available_bytes: u64) {
        self.advisory_available_conn_window = available_bytes;
    }

    /// Association configuration.
    #[inline]
    pub const fn config(&self) -> &AssocConfig {
        &self.config
    }

    /// Mutable access to the association configuration.
    #[inline]
    pub fn config_mut(&mut self) -> &mut AssocConfig {
        &mut self.config
    }

    /// Attach or replace a physical/logical link with `id` and `profile`.
    pub fn upsert_link(&mut self, id: LinkId, profile: LinkProfile) {
        self.links.insert(id, LinkState::new(id, profile));
    }

    /// Borrow a [`LinkState`] by `id`.
    #[inline]
    pub fn link(&self, id: LinkId) -> Option<&LinkState> {
        self.links.get(&id)
    }

    /// Mutably borrow a [`LinkState`] by `id`.
    #[inline]
    pub fn link_mut(&mut self, id: LinkId) -> Option<&mut LinkState> {
        self.links.get_mut(&id)
    }

    /// Iterate over all attached links.
    #[inline]
    pub fn links(&self) -> impl Iterator<Item = (&LinkId, &LinkState)> {
        self.links.iter()
    }

    /// Borrow the underlying [`MultiLinkSackLedger`].
    #[inline]
    pub const fn sack_ledger(&self) -> &MultiLinkSackLedger<P> {
        &self.sack_ledger
    }

    /// Borrow the RX [`AckRangeSet`].
    #[inline]
    pub const fn rx_ack_ranges(&self) -> &AckRangeSet {
        &self.rx_ack_ranges
    }

    /// Number of pending retransmit candidates waiting for an eligible link.
    #[inline]
    pub fn pending_retransmits_len(&self) -> usize {
        self.pending_retransmits.len()
    }

    /// Drain any `(AssociationId, StreamId)` pairs that were evicted from the SACK ledger under
    /// memory pressure so the caller (`QuicMux`) can reset those streams.
    pub fn take_evicted_streams(&mut self) -> Vec<(AssociationId, StreamId)> {
        core::mem::take(&mut self.evicted_streams)
    }

    /// Dynamically adjust `max_retained_packets` in the SACK ledger based on pool pressure,
    /// returning any evicted `(AssociationId, StreamId)` pairs.
    pub fn set_max_retained_tx_packets(
        &mut self,
        max_packets: usize,
    ) -> Vec<(AssociationId, StreamId)> {
        let evicted = self
            .sack_ledger
            .set_max_retained_packets(max_packets, &mut self.links);
        for &(_, sid) in &evicted {
            self.stream_affinity.remove(&sid);
            self.pending_retransmits
                .retain(|c| c.meta.stream_id != Some(sid));
        }
        evicted
    }

    /// Mark `link_id` as down/suspended (or remove it if `remove == true`), evacuating all
    /// unacknowledged packets from `link_id` into `pending_retransmits` and attempting immediate
    /// failover transmission onto any remaining ready links.
    pub fn fail_link(&mut self, link_id: LinkId, remove: bool, now_us: u64) -> usize {
        self.now_us = self.now_us.max(now_us);
        if let Some(link) = self.links.get_mut(&link_id) {
            link.enabled = false;
            link.driver_ready = false;
        }
        self.stream_affinity.retain(|_, &mut lid| lid != link_id);
        let evacuated = self.sack_ledger.evacuate_link(link_id, &mut self.links);
        let count = evacuated.len();
        if remove {
            self.links.remove(&link_id);
        }
        for cand in evacuated {
            self.pending_retransmits.push_back(cand);
        }
        let _ = self.flush_pending_retransmits();
        count
    }

    /// Notify `QuicLinkAssoc` that the physical driver completed transmitting `pkt_num`.
    ///
    /// If `outcome == LinkTxOutcome::Failed`, immediately evacuates `pkt_num` for failover
    /// retransmission onto another link without halving NewReno `cwnd`.
    pub fn on_driver_complete(
        &mut self,
        link_id: LinkId,
        pkt_num: u32,
        outcome: LinkTxOutcome,
        now_us: u64,
    ) -> bool {
        self.now_us = self.now_us.max(now_us);
        if let Some(link) = self.links.get_mut(&link_id) {
            link.on_driver_complete(outcome);
        }
        if let Some(cand) = self
            .sack_ledger
            .on_driver_complete(pkt_num, outcome, &mut self.links)
        {
            if let Some(sid) = cand.meta.stream_id {
                if self.stream_affinity.get(&sid) == Some(&cand.original_link_id) {
                    self.stream_affinity.remove(&sid);
                }
            }
            self.pending_retransmits.push_back(cand);
            let _ = self.flush_pending_retransmits();
            return true;
        }
        false
    }

    /// Pop the next framed outbound packet ready to be handed to a physical link driver.
    #[inline]
    pub fn pop_outbound_packet(&mut self) -> Option<OutboundLinkPacket<P>> {
        self.outbound_queue.pop_front()
    }

    /// Pop the next framed outbound packet specifically targeting `link_id`.
    pub fn pop_outbound_for_link(&mut self, link_id: LinkId) -> Option<OutboundLinkPacket<P>> {
        let idx = self
            .outbound_queue
            .iter()
            .position(|p| p.link_id == link_id)?;
        self.outbound_queue.remove(idx)
    }

    /// Number of framed outbound packets waiting to be pulled by physical link drivers.
    #[inline]
    pub fn outbound_queue_len(&self) -> usize {
        self.outbound_queue.len()
    }

    /// Whether the SACK ledger can currently admit an additional retransmittable packet of `priority`.
    #[inline]
    pub fn can_admit_priority(&self, priority: StreamPriority) -> bool {
        self.sack_ledger.can_admit(priority)
    }

    #[inline]
    fn link_crypto_overhead(&self, link_id: LinkId) -> usize {
        if self.endpoint_keys.is_some() && self.links.get(&link_id).is_some_and(|l| l.profile.encrypt)
        {
            AEAD_TAG_LEN
        } else {
            0
        }
    }

    /// Maximum writable inner frame length (`quic-mux` frame or `DATAGRAM` frame) for a packet of
    /// `priority` at `self.now_us`.
    pub fn max_writable_len_for_priority(&self, priority: StreamPriority) -> usize {
        let emit_initial = self.should_emit_initial(false);
        let has_keys = self.endpoint_keys.is_some();
        let mut best_mtu = 0usize;
        for link in self.links.values() {
            if !link.enabled || !link.driver_ready || priority.is_lower_than(link.profile.max_priority)
            {
                continue;
            }
            let overhead = if emit_initial {
                Self::MAX_INITIAL_OUTER_OVERHEAD
            } else {
                Self::MAX_OUTER_HEADER_OVERHEAD
                    + if has_keys && link.profile.encrypt {
                        AEAD_TAG_LEN
                    } else {
                        0
                    }
            };
            let usable = link.profile.mtu.saturating_sub(overhead);
            if usable > best_mtu {
                best_mtu = usable;
            }
        }
        best_mtu
    }

    /// Select the best ready [`LinkId`] for a packet of `frame_bytes` with `priority` and optional
    /// `stream_id` at `self.now_us`.
    ///
    /// Selection policy:
    /// 1. **Priority filter:** Only considers links with `priority <= link.profile.max_priority`
    ///    that can admit `frame_bytes + ShortHeader` (or `InitialHeader + CRYPTO`) at `self.now_us`.
    /// 2. **Stream affinity:** If `stream_id` is already pinned to an affinity link that can admit
    ///    the packet, keeps the stream on that link unless a strictly lower-tier link has `< 1/2`
    ///    the estimated arrival delay (preventing out-of-order HoL blocking across asymmetric links).
    /// 3. **Tier + Min-Arrival-Delay:** Otherwise selects the candidate link with the lowest
    ///    `(tier, estimated_arrival_delay_us)` — spilling over to a higher-tier link only when lower
    ///    tiers cannot currently admit or have a worse arrival time due to congestion/queueing.
    pub fn select_link(
        &mut self,
        frame_bytes: usize,
        priority: StreamPriority,
        stream_id: Option<StreamId>,
        avoid_link: Option<LinkId>,
        is_pto_probe: bool,
    ) -> Option<LinkId> {
        let now_us = self.now_us;
        let emit_initial = self.should_emit_initial(is_pto_probe);
        let extra_initial_crypto = if emit_initial {
            self.initial_crypto_frame_len().unwrap_or(0)
        } else {
            0
        };
        let has_keys = self.endpoint_keys.is_some();
        let handshake_mode = self.config.handshake_mode;
        let initial_dcid = self.config.initial_dcid;
        let local_cid = self.config.local_cid;
        let peer_scid = self.peer_scid;

        // Collect all eligible links and their `(tier, arrival_delay_us)`.
        let mut candidates: Vec<(LinkId, u8, u64)> = Vec::new();
        for (&id, link) in &mut self.links {
            let hdr_len = if emit_initial {
                Self::initial_header_len_for_link(
                    handshake_mode,
                    initial_dcid,
                    local_cid,
                    peer_scid,
                    link,
                    self.next_pkt_num,
                    extra_initial_crypto.saturating_add(frame_bytes),
                )
            } else {
                Self::header_len_for_link(link, self.next_pkt_num)
            };
            let extra_crypto = if emit_initial {
                extra_initial_crypto
            } else if has_keys && link.profile.encrypt {
                AEAD_TAG_LEN
            } else {
                0
            };
            let total_bytes = frame_bytes.saturating_add(extra_crypto).saturating_add(hdr_len);
            if link.can_admit(total_bytes, priority, now_us, is_pto_probe) {
                let delay = link.estimated_arrival_delay_us(now_us);
                candidates.push((id, link.profile.tier, delay));
            }
        }
        if candidates.is_empty() {
            return None;
        }

        // If avoiding a specific failed link during failover and alternatives exist, filter it out.
        if let Some(avoid) = avoid_link {
            if candidates.iter().any(|&(id, _, _)| id != avoid) {
                candidates.retain(|&(id, _, _)| id != avoid);
            }
        }

        // Find the candidate with the best `(tier, delay)` overall, and also the minimum delay across all candidates.
        let (best_tier_id, best_tier, best_tier_delay) = *candidates
            .iter()
            .min_by_key(|&&(_, tier, delay)| (tier, delay))
            .unwrap();

        // Check if a higher-tier link actually has a significantly smaller arrival delay than `best_tier_id`
        // (e.g. primary link has heavy queue delay).
        let (fastest_id, _, fastest_delay) = *candidates
            .iter()
            .min_by_key(|&&(_, _, delay)| delay)
            .unwrap();

        let chosen = if fastest_delay.saturating_mul(2) < best_tier_delay {
            fastest_id
        } else {
            best_tier_id
        };

        // Check stream affinity if `stream_id` is provided and not avoiding that link.
        if let Some(sid) = stream_id {
            if let Some(&aff_id) = self.stream_affinity.get(&sid) {
                if let Some(&(_, aff_tier, aff_delay)) =
                    candidates.iter().find(|&&(id, _, _)| id == aff_id)
                {
                    // Keep stream affinity unless a lower-tier link has less than half the arrival delay.
                    if aff_tier <= best_tier || best_tier_delay.saturating_mul(2) >= aff_delay {
                        return Some(aff_id);
                    }
                }
            }
            self.stream_affinity.insert(sid, chosen);
        }

        Some(chosen)
    }

    /// Send an unreliable RFC 9221 `DATAGRAM` (`0x30` or `0x31`) with zero payload copies.
    ///
    /// - Caller provides `packet: P` with `packet.range().start` leaving room for the datagram
    ///   header + optional piggybacked `ACK` + `ShortHeader` (standard `DEFAULT_HEADROOM = 144`
    ///   leaves `144` bytes).
    /// - For `priority.is_lower_than(StreamPriority::NORMAL)` (`LOW` / `BULK` datagrams), checks
    ///   `advisory_available_conn_window >= config.datagram.low_priority_window_reserve_bytes`.
    /// - Never retains `packet` in [`MultiLinkSackLedger`].
    pub fn send_datagram(
        &mut self,
        mut packet: P,
        priority: StreamPriority,
    ) -> Result<LinkId, DatagramSendError<P>> {
        if self.config.datagram.max_send_datagram_size == 0 {
            return Err(DatagramSendError::Disabled(packet));
        }
        let payload_len = packet.bytes().len();
        let max_writable = self
            .max_writable_len_for_priority(priority)
            .saturating_sub(4);
        let limit = min(self.config.datagram.max_send_datagram_size, max_writable);
        if payload_len > limit {
            return Err(DatagramSendError::TooLarge {
                packet,
                max_payload_len: limit,
            });
        }
        if priority.is_lower_than(StreamPriority::NORMAL)
            && self.advisory_available_conn_window
                < self.config.datagram.low_priority_window_reserve_bytes
        {
            return Err(DatagramSendError::LowPriorityShed(packet));
        }

        // Select target link first so we know whether `SelfDelimitingStream` requires `0x31` length.
        let estimated_frame_len = payload_len + 3;
        let Some(link_id) = self.select_link(estimated_frame_len, priority, None, None, false)
        else {
            return Err(DatagramSendError::Busy(packet));
        };
        let include_len = matches!(
            self.links[&link_id].profile.framing,
            LinkFraming::SelfDelimitingStream { .. }
        );
        if let Err(e) = prepend_datagram_frame_in_place(&mut packet, include_len) {
            return Err(DatagramSendError::Wire(e, packet));
        }

        let meta = TxPacketMeta {
            association: self.config.assoc_id,
            stream_id: None,
            priority,
            retransmittable: false,
        };
        match self.emit_on_link(link_id, meta, packet, true, false) {
            Ok(()) => {
                if let Some(link) = self.links.get_mut(&link_id) {
                    link.stats.datagrams_sent += 1;
                }
                Ok(link_id)
            }
            Err(pkt) => Err(DatagramSendError::Busy(pkt)),
        }
    }

    /// Receive and demultiplex an incoming wire packet from `link_id` at `now_us`.
    ///
    /// - Reconstructs the 32-bit packet number using RFC 9000 sliding-window decoding.
    /// - Rejects duplicate packet numbers before mutating state.
    /// - Processes any leading `ACK` (`0x02`), `ACK_FREQUENCY` (`0xaf`), `PADDING` (`0x00`), or
    ///   `PING` (`0x01`) frames, and extracts any `DATAGRAM` (`0x30`/`0x31`) frames as zero-copy
    ///   `PoolPacket` slices.
    /// - If inner `quic-mux` frames (`STREAM` `0x08..=0x0f`, `MAX_DATA`, `MAX_STREAM_DATA`,
    ///   `RESET_STREAM`, etc.) remain, sets `mux_packet`'s range to start at the first `quic-mux`
    ///   frame so it can be handed directly to `QuicMux::receive_packet` or [`SingleStreamEndpoint`].
    /// - Updates RX `AckRangeSet` and schedules an immediate or delayed `ACK` (triggering an
    ///   immediate `ACK` on packet reordering or when an incoming `STREAM` carries `FIN` so short
    ///   1–4 packet LoRa/ESP-NOW streams complete without waiting for `max_ack_delay_us`).
    pub fn receive_packet(
        &mut self,
        link_id: LinkId,
        mut packet: P,
        now_us: u64,
    ) -> Result<DemuxOutcome<P>, LinkRecvError> {
        self.now_us = self.now_us.max(now_us);
        let wire_slice = packet.bytes();
        let incoming_is_initial = is_initial_packet(wire_slice);

        let (pn, hdr_len, mut total_len, incoming_scid, incoming_initial_dcid, short_flags, short_pn_len) =
            if incoming_is_initial {
                let (header, hdr_len) =
                    InitialHeader::decode_with_expected(wire_slice, self.expected_rx_pkt_num)
                        .map_err(LinkRecvError::Wire)?;
                match self.config.handshake_mode {
                    HandshakeMode::Server => {
                        if let Some(bound) = self.peer_scid {
                            if header.scid != Some(bound) {
                                return Err(LinkRecvError::UnknownConnectionId(
                                    header.scid.unwrap_or(ConnectionId::new(0).unwrap()),
                                ));
                            }
                        } else if self.server_initial_sent {
                            if let Some(expected_cid) = self.config.local_cid {
                                if header.dcid != Some(expected_cid) {
                                    return Err(LinkRecvError::UnknownConnectionId(
                                        header.dcid.unwrap_or(ConnectionId::new(0).unwrap()),
                                    ));
                                }
                            }
                        }
                    }
                    HandshakeMode::Client | HandshakeMode::None => {
                        if let Some(expected_cid) = self.config.local_cid {
                            if header.dcid != Some(expected_cid) {
                                return Err(LinkRecvError::UnknownConnectionId(
                                    header.dcid.unwrap_or(ConnectionId::new(0).unwrap()),
                                ));
                            }
                        }
                        if let Some(bound) = self.peer_scid {
                            if header.scid != Some(bound) {
                                return Err(LinkRecvError::UnknownConnectionId(
                                    header.scid.unwrap_or(ConnectionId::new(0).unwrap()),
                                ));
                            }
                        }
                    }
                }
                (
                    header.packet_number,
                    hdr_len,
                    hdr_len + header.payload_len,
                    header.scid,
                    header.dcid,
                    0u8,
                    header.packet_number_len,
                )
            } else {
                let (header, hdr_len) =
                    ShortHeader::decode_with_expected(wire_slice, self.expected_rx_pkt_num)
                        .map_err(LinkRecvError::Wire)?;
                if let Some(expected_cid) = self.config.local_cid {
                    if header.dcid != expected_cid {
                        return Err(LinkRecvError::UnknownConnectionId(header.dcid));
                    }
                }
                (
                    header.packet_number,
                    hdr_len,
                    wire_slice.len(),
                    None,
                    None,
                    header.flags,
                    header.packet_number_len,
                )
            };

        if self.rx_ack_ranges.contains(pn) {
            return Err(LinkRecvError::DuplicatePacket(pn));
        }

        // Authenticate and/or decrypt BEFORE mutating any association state.
        let link_requires_encrypt = self
            .links
            .get(&link_id)
            .is_some_and(|l| l.profile.encrypt);
        let verified_initial = if incoming_is_initial {
            self.verify_initial_crypto(
                link_requires_encrypt,
                &packet.bytes()[hdr_len..total_len],
                incoming_scid,
                incoming_initial_dcid,
            )?
        } else {
            if (short_flags & FLAG_PROTECTED) != 0 {
                let Some(ref keys) = self.endpoint_keys else {
                    return Err(LinkRecvError::Crypto(CryptoError::AuthenticationFailed));
                };
                open_short_packet_in_place(
                    &mut packet,
                    &keys.receive,
                    short_flags,
                    hdr_len,
                    pn,
                    short_pn_len,
                    self.local_endpoint_dcid,
                )
                .map_err(LinkRecvError::Crypto)?;
                total_len = packet.bytes().len();
            } else if link_requires_encrypt
                && (self.endpoint_keys.is_some() || self.crypto_config.is_some())
            {
                return Err(LinkRecvError::Crypto(CryptoError::AuthenticationFailed));
            }
            None
        };

        let base_range = packet.range();
        let mut cursor = hdr_len;

        let mut had_ack = false;
        let mut newly_acked_packets = 0usize;
        let mut retransmit_candidates = Vec::new();
        let mut datagrams = Vec::new();
        let mut ack_eliciting = false;
        let mut saw_fin = false;
        let mut first_mux_offset: Option<usize> = None;
        let mut last_mux_end: usize = total_len;
        let mut parsed_peer_params: Option<TransportParameters> = None;

        // Parse leading link-layer frames (`PADDING`, `PING`, `ACK`, `CRYPTO`, `ACK_FREQUENCY`, `DATAGRAM`).
        while cursor < total_len {
            let (ty, n_ty) = decode_varint(&packet.bytes()[cursor..total_len])
                .map_err(LinkRecvError::Wire)?;
            match ty {
                FRAME_PADDING => {
                    cursor += n_ty;
                }
                FRAME_PING => {
                    ack_eliciting = true;
                    cursor += n_ty;
                }
                FRAME_CRYPTO => {
                    let (offset, data_range, next_at) =
                        decode_crypto_frame_body(&packet.bytes()[..total_len], cursor + n_ty)
                            .map_err(LinkRecvError::Wire)?;
                    ack_eliciting = true;
                    if offset == 0 {
                        let params = TransportParameters::decode(&packet.bytes()[data_range])
                            .map_err(LinkRecvError::Wire)?;
                        parsed_peer_params = Some(params);
                    }
                    cursor = next_at;
                }
                FRAME_ACK => {
                    let (_largest, delay_us, ack_ranges, next_at) =
                        decode_ack_frame_body(packet.bytes(), cursor + n_ty)
                            .map_err(LinkRecvError::Wire)?;
                    cursor = next_at;
                    had_ack = true;
                    let outcome: AckProcessOutcome<P> = self.sack_ledger.on_ack_frame(
                        &ack_ranges,
                        delay_us,
                        self.config.max_ack_delay_us,
                        self.now_us,
                        &mut self.links,
                    );
                    newly_acked_packets += outcome.newly_acked_packets;
                    retransmit_candidates.extend(outcome.retransmit_candidates);
                }
                FRAME_ACK_FREQUENCY => {
                    let mut at = cursor + n_ty;
                    let bytes = packet.bytes();
                    let (seq, n1) = decode_varint(bytes.get(at..).ok_or(WireError::UnexpectedEof).map_err(LinkRecvError::Wire)?)
                        .map_err(LinkRecvError::Wire)?;
                    at += n1;
                    let (pkt_thresh, n2) = decode_varint(bytes.get(at..).ok_or(WireError::UnexpectedEof).map_err(LinkRecvError::Wire)?)
                        .map_err(LinkRecvError::Wire)?;
                    at += n2;
                    let (max_delay, n3) = decode_varint(bytes.get(at..).ok_or(WireError::UnexpectedEof).map_err(LinkRecvError::Wire)?)
                        .map_err(LinkRecvError::Wire)?;
                    at += n3;
                    let (reord, n4) = decode_varint(bytes.get(at..).ok_or(WireError::UnexpectedEof).map_err(LinkRecvError::Wire)?)
                        .map_err(LinkRecvError::Wire)?;
                    at += n4;
                    cursor = at;
                    ack_eliciting = true;
                    if self.last_ack_freq_seq.is_none_or(|prev| seq > prev) {
                        self.last_ack_freq_seq = Some(seq);
                        self.config.ack_eliciting_threshold = (pkt_thresh as u32).max(1);
                        self.config.max_ack_delay_us = max_delay;
                        self.rx_reordering_threshold = (reord as u32).max(1);
                    }
                }
                FRAME_DATAGRAM | FRAME_DATAGRAM_LEN => {
                    ack_eliciting = true;
                    let mut at = cursor + n_ty;
                    let payload_len = if ty == FRAME_DATAGRAM_LEN {
                        let (l, nl) = decode_varint(
                            packet
                                .bytes()
                                .get(at..)
                                .ok_or(WireError::UnexpectedEof)
                                .map_err(LinkRecvError::Wire)?,
                        )
                        .map_err(LinkRecvError::Wire)?;
                        at += nl;
                        usize::try_from(l).map_err(|_| LinkRecvError::Wire(WireError::InvalidFrame))?
                    } else {
                        total_len.saturating_sub(at)
                    };
                    if payload_len > self.config.datagram.max_recv_datagram_size {
                        return Err(LinkRecvError::DatagramTooLarge(payload_len));
                    }
                    let end = at
                        .checked_add(payload_len)
                        .ok_or(LinkRecvError::Wire(WireError::InvalidFrame))?;
                    if end > total_len {
                        return Err(LinkRecvError::Wire(WireError::UnexpectedEof));
                    }
                    let abs_range = (base_range.start + at)..(base_range.start + end);
                    if let Ok(mut dgram_pkt) = packet.try_clone() {
                        let _ = dgram_pkt.set_range(abs_range);
                        datagrams.push(dgram_pkt);
                    }
                    cursor = end;
                }
                _ => {
                    // Inner `quic-mux` frame (`STREAM`, `MAX_DATA`, `MAX_STREAM_DATA`, `RESET_STREAM`, etc.)
                    ack_eliciting = true;
                    if first_mux_offset.is_none() {
                        first_mux_offset = Some(cursor);
                    }
                    let slice = &packet.bytes()[cursor..total_len];
                    let (mux_frame, rel_next) =
                        decode_frame(slice, 0).map_err(LinkRecvError::Wire)?;
                    if let Frame::Stream(ref sf) = mux_frame {
                        if sf.fin {
                            saw_fin = true;
                        }
                    }
                    cursor += rel_next;
                    last_mux_end = cursor;
                }
            }
        }

        // Packet validated: record in `rx_ack_ranges` and update `expected_rx_pkt_num`.
        let prev_largest = self.rx_ack_ranges.largest();
        self.rx_ack_ranges.insert(pn);
        self.last_rx_pkt_num = Some(pn);
        if pn >= self.expected_rx_pkt_num {
            self.expected_rx_pkt_num = pn.saturating_add(1);
        }
        if prev_largest.is_none_or(|prev| pn > prev) {
            self.rx_largest_received_at_us = Some(self.now_us);
        }

        if let Some(params) = parsed_peer_params {
            self.peer_params = Some(params);
        }
        if let Some(vi) = verified_initial {
            self.endpoint_keys = Some(vi.keys);
            self.local_endpoint_dcid = vi.local_dcid;
            self.peer_endpoint_dcid = vi.peer_dcid;
            if let Some((original_dcid, verifier)) = vi.server_response {
                self.config.local_params.original_dcid = original_dcid;
                self.config.local_params.verifier = verifier;
            }
        }
        let learned_scid = incoming_scid.or_else(|| parsed_peer_params.and_then(|p| p.initial_scid));
        match self.config.handshake_mode {
            HandshakeMode::Server => {
                if incoming_is_initial {
                    if let Some(scid) = learned_scid {
                        self.peer_scid = Some(scid);
                        self.set_peer_cid_all_links(scid);
                    }
                    if !self.handshake_complete
                        && (!self.server_initial_sent || self.outbound_queue.is_empty())
                    {
                        self.server_initial_needed = true;
                        self.rx_immediate_ack_pending = true;
                        self.rx_ack_deadline_us = Some(self.now_us);
                    }
                } else {
                    self.handshake_complete = true;
                    self.server_initial_needed = false;
                }
                if newly_acked_packets > 0 && self.peer_scid.is_some() {
                    self.handshake_complete = true;
                    self.server_initial_needed = false;
                }
            }
            HandshakeMode::Client => {
                if incoming_is_initial {
                    if let Some(scid) = learned_scid {
                        self.peer_scid = Some(scid);
                        self.set_peer_cid_all_links(scid);
                    }
                    self.handshake_complete = true;
                    self.rx_immediate_ack_pending = true;
                    self.rx_ack_deadline_us = Some(self.now_us);
                }
            }
            HandshakeMode::None => {}
        }

        if ack_eliciting {
            self.rx_ack_eliciting_since_last_ack =
                self.rx_ack_eliciting_since_last_ack.saturating_add(1);
            let out_of_order = prev_largest.is_some_and(|largest| {
                pn < largest
                    || pn.saturating_sub(largest) > self.rx_reordering_threshold.max(1)
            });
            if self.rx_ack_eliciting_since_last_ack >= self.config.ack_eliciting_threshold
                || out_of_order
                || saw_fin
                || self.config.max_ack_delay_us == 0
            {
                self.rx_immediate_ack_pending = true;
                self.rx_ack_deadline_us = Some(self.now_us);
            } else if self.rx_ack_deadline_us.is_none() {
                self.rx_ack_deadline_us =
                    Some(self.now_us.saturating_add(self.config.max_ack_delay_us));
            }
        }

        let mux_packet = if let Some(mux_start) = first_mux_offset {
            let abs_mux_range =
                (base_range.start + mux_start)..(base_range.start + last_mux_end);
            let _ = packet.set_range(abs_mux_range);
            Some(packet)
        } else {
            // Drop `packet` now so that if `datagrams` extracted a sole `DATAGRAM` frame via
            // `try_clone()`, that datagram `PoolPacket` is uniquely owned (`is_unique() == true`).
            drop(packet);
            None
        };

        // Queue and attempt to flush any retransmit candidates discovered by the incoming ACK.
        let retransmits_queued = retransmit_candidates.len();
        for cand in retransmit_candidates {
            self.pending_retransmits.push_back(cand);
        }
        let _ = self.flush_pending_retransmits();

        Ok(DemuxOutcome {
            packet_number: pn,
            link_id,
            is_initial: incoming_is_initial,
            peer_scid: learned_scid,
            peer_params: parsed_peer_params,
            had_ack,
            newly_acked_packets,
            retransmits_queued,
            datagrams,
            mux_packet,
        })
    }

    /// Poll time-based events at `now_us` (delayed `ACK` expiration, per-link time-threshold loss,
    /// PTO timeouts, and pending retransmissions), using `pool` when a standalone `ACK` packet
    /// must be allocated.
    pub fn poll_timers<Pool: PacketPool<Packet = P>>(
        &mut self,
        pool: &mut Pool,
        now_us: u64,
    ) -> usize {
        self.now_us = self.now_us.max(now_us);
        let mut emitted = 0usize;

        // 1. Check per-link time-threshold losses and PTO expirations.
        let time_losses = self.sack_ledger.detect_losses(
            self.config.max_ack_delay_us,
            self.now_us,
            &mut self.links,
        );
        for cand in time_losses {
            self.pending_retransmits.push_back(cand);
        }

        let pto_losses = self.sack_ledger.collect_pto_retransmits(
            self.config.max_ack_delay_us,
            self.now_us,
            &mut self.links,
        );
        for cand in pto_losses {
            self.pending_retransmits.push_back(cand);
        }

        // 2. Flush any pending retransmits onto ready links.
        emitted += self.flush_pending_retransmits();

        // 3. Emit Server `Initial` (`CRYPTO` + piggybacked `ACK`) before standalone ShortHeader ACKs
        //    if a Server association has accepted Client `Initial` without yet sending its reply.
        if self.config.handshake_mode == HandshakeMode::Server && self.server_initial_needed {
            if self.enqueue_initial(pool).is_ok() {
                emitted += 1;
            }
        }

        // 4. If an immediate or delayed ACK is due and wasn't already piggybacked onto an outbound
        //    packet, emit a standalone ACK packet once Initial exchange is not pending.
        if !self.should_emit_initial(false) && self.should_send_standalone_ack(self.now_us) {
            if self.emit_standalone_ack(pool).is_ok() {
                emitted += 1;
            }
        }

        emitted
    }

    /// Flush as many `pending_retransmits` as currently ready links will admit.
    pub fn flush_pending_retransmits(&mut self) -> usize {
        let mut sent = 0usize;
        let count = self.pending_retransmits.len();
        for _ in 0..count {
            let Some(mut cand) = self.pending_retransmits.pop_front() else {
                break;
            };
            if cand.is_sealed {
                let Some(ref keys) = self.endpoint_keys else {
                    continue;
                };
                if !cand.packet.is_unique() {
                    self.pending_retransmits.push_back(cand);
                    continue;
                }
                let Ok((sh, hdr_len)) =
                    ShortHeader::decode_with_expected(cand.packet.bytes(), cand.original_pkt_num)
                else {
                    continue;
                };
                let pre_open_start = cand.packet.range().start;
                if let Err(err) = open_short_packet_in_place(
                    &mut cand.packet,
                    &keys.send,
                    sh.flags,
                    hdr_len,
                    cand.original_pkt_num,
                    sh.packet_number_len,
                    self.peer_endpoint_dcid,
                ) {
                    if matches!(
                        err,
                        CryptoError::BufferTooSmall | CryptoError::SharedPacket
                    ) {
                        self.pending_retransmits.push_back(cand);
                    }
                    continue;
                }
                let delta = cand.packet.range().start as isize - pre_open_start as isize;
                cand.mux_range = ((cand.mux_range.start as isize + delta) as usize)
                    ..((cand.mux_range.end as isize + delta) as usize);
                cand.is_sealed = false;
            }
            if cand.packet.set_range(cand.mux_range.clone()).is_err() {
                continue;
            }
            let frame_len = cand.packet.bytes().len();
            let Some(link_id) = self.select_link(
                frame_len,
                cand.meta.priority,
                cand.meta.stream_id,
                Some(cand.original_link_id),
                true,
            ) else {
                self.pending_retransmits.push_back(cand);
                continue;
            };
            match self.emit_on_link(link_id, cand.meta, cand.packet, true, true) {
                Ok(()) => {
                    if let Some(link) = self.links.get_mut(&link_id) {
                        link.stats.retransmissions_sent += 1;
                    }
                    sent += 1;
                }
                Err(pkt) => {
                    self.pending_retransmits.push_back(LinkRetransmitCandidate {
                        original_pkt_num: cand.original_pkt_num,
                        original_link_id: cand.original_link_id,
                        meta: cand.meta,
                        mux_range: cand.mux_range,
                        is_sealed: false,
                        packet: pkt,
                    });
                }
            }
        }
        sent
    }

    /// Force emitting a standalone `ACK` packet if any RX packet numbers have been recorded.
    pub fn emit_standalone_ack<Pool: PacketPool<Packet = P>>(
        &mut self,
        pool: &mut Pool,
    ) -> Result<LinkId, PoolError> {
        if self.rx_ack_ranges.is_empty() {
            return Ok(LinkId(0));
        }
        let mut pkt = pool.alloc()?;
        let delay_us = self
            .rx_largest_received_at_us
            .map_or(0, |t| self.now_us.saturating_sub(t));
        let mut ack_buf = [0u8; 256];
        let Ok(ack_len) = encode_ack_frame(&self.rx_ack_ranges, delay_us, &mut ack_buf) else {
            return Ok(LinkId(0));
        };
        pkt.append(&ack_buf[..ack_len])?;

        let Some(link_id) = self.select_link(ack_len, StreamPriority::CRITICAL, None, None, true)
        else {
            return Ok(LinkId(0));
        };
        let meta = TxPacketMeta {
            association: self.config.assoc_id,
            stream_id: None,
            priority: StreamPriority::CRITICAL,
            retransmittable: false,
        };
        if self.emit_ack_only_on_link(link_id, meta, pkt).is_ok() {
            self.clear_pending_ack_state();
        }
        Ok(link_id)
    }

    /// Send an `ACK_FREQUENCY` (`0xaf`) control frame to the peer.
    pub fn send_ack_frequency<Pool: PacketPool<Packet = P>>(
        &mut self,
        pool: &mut Pool,
        frame: &AckFrequencyFrame,
    ) -> Result<(), PoolError> {
        let mut pkt = pool.alloc()?;
        let mut buf = [0u8; 40];
        let Ok(n) = crate::wire::encode_ack_frequency_frame(frame, &mut buf) else {
            return Ok(());
        };
        pkt.append(&buf[..n])?;
        let meta = TxPacketMeta {
            association: self.config.assoc_id,
            stream_id: None,
            priority: StreamPriority::CRITICAL,
            retransmittable: true,
        };
        let _ = self.send_packet(meta, pkt);
        Ok(())
    }

    /// Next earliest timer deadline (`ACK` delay, pacing deadline, loss timer, or PTO timer).
    pub fn next_deadline_us(&self) -> Option<u64> {
        let mut earliest = self.rx_ack_deadline_us;
        if let Some(sack_dl) = self
            .sack_ledger
            .next_deadline_us(self.config.max_ack_delay_us, &self.links)
        {
            earliest = Some(earliest.map_or(sack_dl, |cur| cur.min(sack_dl)));
        }
        for link in self.links.values() {
            if let Some(p_dl) = link.pacing_deadline_us() {
                earliest = Some(earliest.map_or(p_dl, |cur| cur.min(p_dl)));
            }
        }
        earliest
    }

    fn should_send_standalone_ack(&self, now_us: u64) -> bool {
        if self.rx_ack_ranges.is_empty() {
            return false;
        }
        if self.rx_immediate_ack_pending {
            return true;
        }
        self.rx_ack_deadline_us.is_some_and(|dl| now_us >= dl)
    }

    fn clear_pending_ack_state(&mut self) {
        self.rx_ack_eliciting_since_last_ack = 0;
        self.rx_immediate_ack_pending = false;
        self.rx_ack_deadline_us = None;
    }

    fn should_emit_initial(&self, is_pto_probe: bool) -> bool {
        match self.config.handshake_mode {
            HandshakeMode::None => false,
            HandshakeMode::Client => !self.handshake_complete,
            HandshakeMode::Server => {
                self.server_initial_needed
                    || (is_pto_probe && !self.handshake_complete && self.peer_scid.is_some())
            }
        }
    }

    fn resolved_local_params(&self) -> TransportParameters {
        let mut params = self.config.local_params;
        if params.initial_scid.is_none() {
            params.initial_scid = self.config.local_cid;
        }
        params
    }

    fn initial_crypto_frame_len(&self) -> Result<usize, WireError> {
        let tp_len = self.resolved_local_params().encoded_len()?;
        Ok(1 + 1 + varint_len(tp_len as u64)? + tp_len)
    }

    fn build_crypto_frame(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut tp_buf = [0u8; 192];
        let tp_len = self.resolved_local_params().encode(&mut tp_buf)?;
        encode_crypto_frame(0, &tp_buf[..tp_len], out)
    }

    fn initial_dcid_for_link(&self, link: &LinkState) -> Option<ConnectionId> {
        match self.config.handshake_mode {
            HandshakeMode::Client => self.config.initial_dcid,
            HandshakeMode::Server => self.peer_scid.or_else(|| Some(self.peer_cid_for_link(link))),
            HandshakeMode::None => None,
        }
    }

    fn initial_header_len_for_link(
        handshake_mode: HandshakeMode,
        initial_dcid: Option<ConnectionId>,
        local_cid: Option<ConnectionId>,
        peer_scid: Option<ConnectionId>,
        link: &LinkState,
        pkt_num: u32,
        payload_len: usize,
    ) -> usize {
        let resolved_dcid = match handshake_mode {
            HandshakeMode::Client => initial_dcid,
            HandshakeMode::Server => peer_scid.or(match link.profile.framing {
                LinkFraming::Datagram { peer_cid }
                | LinkFraming::SelfDelimitingStream { peer_cid }
                | LinkFraming::TlsRecord { peer_cid } => Some(peer_cid),
            }),
            HandshakeMode::None => None,
        };
        let dcid_len = resolved_dcid.map_or(0, ConnectionId::encoded_len);
        let scid_len = local_cid.map_or(0, ConnectionId::encoded_len);
        let pn_len = packet_number_len(pkt_num, link.largest_acked_packet) as usize;
        let body_len = (pn_len + payload_len.max(1)) as u64;
        let len_bytes = varint_len(body_len).unwrap_or(2);
        1 + 4 + 1 + dcid_len + 1 + scid_len + 1 + len_bytes + pn_len
    }

    fn peer_cid_for_link(&self, link: &LinkState) -> ConnectionId {
        match link.profile.framing {
            LinkFraming::Datagram { peer_cid }
            | LinkFraming::SelfDelimitingStream { peer_cid }
            | LinkFraming::TlsRecord { peer_cid } => peer_cid,
        }
    }

    fn header_len_for_link(link: &LinkState, pkt_num: u32) -> usize {
        let cid_len = match link.profile.framing {
            LinkFraming::Datagram { peer_cid }
            | LinkFraming::SelfDelimitingStream { peer_cid }
            | LinkFraming::TlsRecord { peer_cid } => peer_cid.encoded_len(),
        };
        let pn_len = packet_number_len(pkt_num, link.largest_acked_packet) as usize;
        1 + cid_len + pn_len
    }

    fn try_coalesce_onto_pending(
        &mut self,
        link_id: LinkId,
        incoming_meta: TxPacketMeta,
        incoming: P,
    ) -> Result<(), P> {
        if self.should_emit_initial(false) || self.link_crypto_overhead(link_id) > 0 {
            return Err(incoming);
        }
        let Some(link) = self.links.get(&link_id) else {
            return Err(incoming);
        };
        if matches!(link.profile.framing, LinkFraming::SelfDelimitingStream { .. }) {
            return Err(incoming);
        }
        let mtu = link.profile.mtu;
        let hdr_len = Self::header_len_for_link(link, self.next_pkt_num);
        let max_inner_mtu = mtu.saturating_sub(hdr_len);
        let coalesce_thresh = default_coalesce_threshold(max_inner_mtu);
        if incoming.bytes().len() > coalesce_thresh {
            return Err(incoming);
        }

        // Check if there is an already-queued outbound packet for `link_id` that hasn't been
        // handed to the driver yet and is not already retained in `sack_ledger` (i.e. unique).
        let Some(queued) = self
            .outbound_queue
            .iter_mut()
            .rev()
            .find(|p| p.link_id == link_id && p.packet.is_unique() && !is_initial_packet(p.packet.bytes()))
        else {
            return Err(incoming);
        };

        try_coalesce_tx_packet(
            &mut queued.meta,
            &mut queued.packet,
            incoming_meta,
            incoming,
            mtu,
            coalesce_thresh,
        )
    }

    fn seal_short_header_packet(
        &self,
        link_id: LinkId,
        pkt_num: u32,
        packet: &mut P,
    ) -> Result<bool, ()> {
        if !self.links.get(&link_id).is_some_and(|l| l.profile.encrypt) {
            return Ok(false);
        }
        if let Some(ref keys) = self.endpoint_keys {
            return seal_short_packet_in_place_with_pn(
                packet,
                &keys.send,
                pkt_num,
                self.peer_endpoint_dcid,
            )
            .map(|()| true)
            .map_err(|_| ());
        }
        if self.crypto_config.is_some() {
            return Err(());
        }
        Ok(false)
    }

    fn verify_initial_crypto(
        &self,
        link_requires_encrypt: bool,
        wire: &[u8],
        incoming_scid: Option<ConnectionId>,
        incoming_initial_dcid: Option<ConnectionId>,
    ) -> Result<Option<VerifiedInitial>, LinkRecvError> {
        let Some(cfg) = self.crypto_config else {
            return Ok(None);
        };
        if self.config.handshake_mode == HandshakeMode::None {
            return Err(LinkRecvError::Crypto(CryptoError::AuthenticationFailed));
        }
        let Some(peer_params) = find_initial_crypto_params(wire)? else {
            if !link_requires_encrypt {
                return Ok(None);
            }
            return Err(LinkRecvError::Crypto(CryptoError::AuthenticationFailed));
        };
        if !link_requires_encrypt && peer_params.verifier.is_none() {
            return Ok(None);
        }
        let peer_pub = peer_params
            .public_key
            .ok_or(LinkRecvError::Crypto(CryptoError::AuthenticationFailed))?;
        let peer_rand = peer_params
            .random
            .ok_or(LinkRecvError::Crypto(CryptoError::AuthenticationFailed))?;
        let peer_verifier = peer_params
            .verifier
            .ok_or(LinkRecvError::Crypto(CryptoError::AuthenticationFailed))?;
        let peer_scid = incoming_scid
            .or(peer_params.initial_scid)
            .ok_or(LinkRecvError::Crypto(CryptoError::Invalid))?;
        let local_cid = self
            .config
            .local_cid
            .ok_or(LinkRecvError::Crypto(CryptoError::Invalid))?;

        match self.config.handshake_mode {
            HandshakeMode::Server => {
                let api_key = match (cfg.send_api_key, cfg.node_secret) {
                    (Some(k), _) => k,
                    (None, Some(ns)) => {
                        derive_peer_api_key_with(&cfg.provider, &ns, &peer_pub)
                            .map_err(LinkRecvError::Crypto)?
                    }
                    (None, None) => return Err(LinkRecvError::Crypto(CryptoError::Invalid)),
                };
                let ok = verify_initial_verifier_with(
                    &cfg.provider,
                    &api_key,
                    CryptoRole::Client,
                    Some(peer_scid),
                    incoming_initial_dcid,
                    &peer_pub,
                    &peer_rand,
                    &peer_verifier,
                )
                .map_err(LinkRecvError::Crypto)?;
                if !ok {
                    return Err(LinkRecvError::Crypto(CryptoError::AuthenticationFailed));
                }
                let keys = derive_traffic_keys_with(
                    &cfg.provider,
                    &api_key,
                    &peer_rand,
                    &cfg.local_random,
                    peer_scid,
                    local_cid,
                )
                .map_err(LinkRecvError::Crypto)?
                .for_role(CryptoRole::Server);
                let srv_verifier = match cfg.local_public_key {
                    Some(srv_pub) => Some(
                        compute_initial_verifier_with(
                            &cfg.provider,
                            &api_key,
                            CryptoRole::Server,
                            Some(local_cid),
                            incoming_initial_dcid,
                            &srv_pub,
                            &cfg.local_random,
                        )
                        .map_err(LinkRecvError::Crypto)?,
                    ),
                    None => None,
                };
                Ok(Some(VerifiedInitial {
                    keys,
                    local_dcid: local_cid,
                    peer_dcid: peer_scid,
                    server_response: Some((incoming_initial_dcid, srv_verifier)),
                }))
            }
            HandshakeMode::Client => {
                let api_key = cfg
                    .send_api_key
                    .ok_or(LinkRecvError::Crypto(CryptoError::Invalid))?;
                if self.config.initial_dcid.is_some()
                    && peer_params.original_dcid != self.config.initial_dcid
                {
                    return Err(LinkRecvError::Crypto(CryptoError::AuthenticationFailed));
                }
                let ok = verify_initial_verifier_with(
                    &cfg.provider,
                    &api_key,
                    CryptoRole::Server,
                    Some(peer_scid),
                    peer_params.original_dcid,
                    &peer_pub,
                    &peer_rand,
                    &peer_verifier,
                )
                .map_err(LinkRecvError::Crypto)?;
                if !ok {
                    return Err(LinkRecvError::Crypto(CryptoError::AuthenticationFailed));
                }
                let keys = derive_traffic_keys_with(
                    &cfg.provider,
                    &api_key,
                    &cfg.local_random,
                    &peer_rand,
                    local_cid,
                    peer_scid,
                )
                .map_err(LinkRecvError::Crypto)?
                .for_role(CryptoRole::Client);
                Ok(Some(VerifiedInitial {
                    keys,
                    local_dcid: local_cid,
                    peer_dcid: peer_scid,
                    server_response: None,
                }))
            }
            HandshakeMode::None => unreachable!(),
        }
    }

    fn emit_on_link(
        &mut self,
        link_id: LinkId,
        meta: TxPacketMeta,
        mut packet: P,
        ack_eliciting: bool,
        is_pto_probe: bool,
    ) -> Result<(), P> {
        // 1. If non-retransmittable or unique, try small-packet coalescing first.
        if !meta.retransmittable {
            if let Err(returned) = self.try_coalesce_onto_pending(link_id, meta, packet) {
                packet = returned;
            } else {
                return Ok(());
            }
        }

        if meta.retransmittable && !self.sack_ledger.can_admit(meta.priority) {
            return Err(packet);
        }

        let pkt_num = self.next_pkt_num;
        let emit_initial = self.should_emit_initial(is_pto_probe);
        let mut crypto_buf = [0u8; 208];
        let crypto_len = if emit_initial {
            let Ok(len) = self.build_crypto_frame(&mut crypto_buf) else {
                return Err(packet);
            };
            len
        } else {
            0
        };

        let is_stream_framed = matches!(
            self.links[&link_id].profile.framing,
            LinkFraming::SelfDelimitingStream { .. }
        );
        let want_piggyback_ack = !is_stream_framed
            && !self.rx_ack_ranges.is_empty()
            && (self.rx_immediate_ack_pending
                || self.rx_ack_eliciting_since_last_ack > 0
                || self.rx_ack_deadline_us.is_some());

        let mut ack_buf = [0u8; 128];
        let mut ack_len = 0usize;
        if want_piggyback_ack {
            let delay_us = self
                .rx_largest_received_at_us
                .map_or(0, |t| self.now_us.saturating_sub(t));
            if let Ok(n) = encode_ack_frame(&self.rx_ack_ranges, delay_us, &mut ack_buf) {
                ack_len = n;
            }
        }

        let link_mtu = self.links[&link_id].profile.mtu;
        let hdr_len_est = if emit_initial {
            Self::initial_header_len_for_link(
                self.config.handshake_mode,
                self.config.initial_dcid,
                self.config.local_cid,
                self.peer_scid,
                &self.links[&link_id],
                pkt_num,
                crypto_len + packet.bytes().len() + ack_len,
            )
        } else {
            Self::header_len_for_link(&self.links[&link_id], pkt_num)
        };
        let extra_tag = if emit_initial {
            0
        } else {
            self.link_crypto_overhead(link_id)
        };

        // Ensure enough headroom in front of the inner payload when `emit_initial` exceeds
        // `DEFAULT_HEADROOM`, right-shifting into slot tailroom if available.
        let mut include_ack = false;
        if ack_len > 0 {
            let need_with_ack = hdr_len_est + crypto_len + ack_len;
            let shift = need_with_ack.saturating_sub(packet.range().start);
            let projected_with_ack = need_with_ack + packet.bytes().len() + extra_tag;
            if projected_with_ack <= link_mtu
                && (shift == 0 || (emit_initial && packet.tailroom() >= shift))
            {
                if shift == 0 || shift_packet_right(&mut packet, shift).is_ok() {
                    include_ack = true;
                }
            }
        }
        if !include_ack && emit_initial {
            let need = hdr_len_est + crypto_len;
            let shift = need.saturating_sub(packet.range().start);
            if shift > 0 {
                if packet.tailroom() < shift || shift_packet_right(&mut packet, shift).is_err() {
                    return Err(packet);
                }
            }
        }

        let inner_frame_range = packet.range();
        let mut carries_ack = false;
        if include_ack && packet.prepend(&ack_buf[..ack_len]).is_ok() {
            carries_ack = true;
            self.clear_pending_ack_state();
        }

        // Prepend outer header (`InitialHeader + CRYPTO` or `ShortHeader`) and seal if enabled.
        let largest_acked = self.links[&link_id].largest_acked_packet;
        let pn_len = packet_number_len(pkt_num, largest_acked);
        if emit_initial {
            if packet.prepend(&crypto_buf[..crypto_len]).is_err() {
                let _ = packet.set_range(inner_frame_range);
                return Err(packet);
            }
            let dcid = self.initial_dcid_for_link(&self.links[&link_id]);
            let init_hdr = InitialHeader {
                version: DMESH_QUIC_VERSION,
                dcid,
                scid: self.config.local_cid,
                packet_number: pkt_num,
                packet_number_len: pn_len,
                payload_len: packet.bytes().len(),
            };
            let mut hdr_buf = [0u8; InitialHeader::MAX_LEN];
            let Ok(hdr_len) = init_hdr.encode(&mut hdr_buf) else {
                let _ = packet.set_range(inner_frame_range);
                return Err(packet);
            };
            if packet.prepend(&hdr_buf[..hdr_len]).is_err() {
                let _ = packet.set_range(inner_frame_range);
                return Err(packet);
            }
        } else {
            let dcid = self.peer_cid_for_link(&self.links[&link_id]);
            let short_hdr = ShortHeader {
                flags: 0,
                dcid,
                packet_number: pkt_num,
                packet_number_len: pn_len,
            };
            let mut hdr_buf = [0u8; ShortHeader::MAX_LEN];
            let Ok(hdr_len) = short_hdr.encode(&mut hdr_buf) else {
                let _ = packet.set_range(inner_frame_range);
                return Err(packet);
            };
            if packet.prepend(&hdr_buf[..hdr_len]).is_err() {
                let _ = packet.set_range(inner_frame_range);
                return Err(packet);
            }
        }

        let pre_seal_start = packet.range().start;
        let is_sealed = if !emit_initial {
            match self.seal_short_header_packet(link_id, pkt_num, &mut packet) {
                Ok(sealed) => sealed,
                Err(()) => {
                    let _ = packet.set_range(inner_frame_range);
                    return Err(packet);
                }
            }
        } else {
            false
        };
        let sealed_inner_range = if is_sealed {
            let delta = packet.range().start as isize - pre_seal_start as isize;
            ((inner_frame_range.start as isize + delta) as usize)
                ..((inner_frame_range.end as isize + delta) as usize)
        } else {
            inner_frame_range.clone()
        };

        let wire_bytes = packet.bytes().len();
        let retained_clone = if meta.retransmittable {
            match packet.try_clone() {
                Ok(c) => Some(c),
                Err(_) => {
                    let _ = packet.set_range(sealed_inner_range);
                    return Err(packet);
                }
            }
        } else {
            None
        };

        self.next_pkt_num = self.next_pkt_num.saturating_add(1);
        let (send_order, window_limited) = self.links.get_mut(&link_id).unwrap().record_packet_sent(
            pkt_num,
            wire_bytes,
            self.now_us,
            ack_eliciting,
            is_pto_probe,
        );

        match self.sack_ledger.record_tx(
            pkt_num,
            link_id,
            send_order,
            wire_bytes,
            self.now_us,
            sealed_inner_range,
            is_sealed,
            meta,
            window_limited,
            retained_clone,
            &mut self.links,
        ) {
            Ok(evicted) => {
                for v in evicted {
                    if !self.evicted_streams.contains(&v) {
                        self.evicted_streams.push(v);
                    }
                }
            }
            Err(_) => {
                let _ = packet.set_range(inner_frame_range);
                return Err(packet);
            }
        }

        if emit_initial && self.config.handshake_mode == HandshakeMode::Server {
            self.server_initial_needed = false;
            self.server_initial_sent = true;
        }

        self.outbound_queue.push_back(OutboundLinkPacket {
            link_id,
            packet_number: pkt_num,
            meta,
            inner_frame_range,
            carries_ack,
            ack_eliciting,
            packet,
        });
        Ok(())
    }

    fn emit_ack_only_on_link(
        &mut self,
        link_id: LinkId,
        meta: TxPacketMeta,
        mut packet: P,
    ) -> Result<(), P> {
        let inner_frame_range = packet.range();
        let pkt_num = self.next_pkt_num;
        let dcid = self.peer_cid_for_link(&self.links[&link_id]);
        let largest_acked = self.links[&link_id].largest_acked_packet;
        let pn_len = packet_number_len(pkt_num, largest_acked);
        let short_hdr = ShortHeader {
            flags: 0,
            dcid,
            packet_number: pkt_num,
            packet_number_len: pn_len,
        };
        let mut hdr_buf = [0u8; ShortHeader::MAX_LEN];
        let Ok(hdr_len) = short_hdr.encode(&mut hdr_buf) else {
            return Err(packet);
        };
        if packet.prepend(&hdr_buf[..hdr_len]).is_err() {
            return Err(packet);
        }
        if self
            .seal_short_header_packet(link_id, pkt_num, &mut packet)
            .is_err()
        {
            let _ = packet.set_range(inner_frame_range);
            return Err(packet);
        }
        let wire_bytes = packet.bytes().len();
        self.next_pkt_num = self.next_pkt_num.saturating_add(1);
        let _ = self.links.get_mut(&link_id).unwrap().record_packet_sent(
            pkt_num,
            wire_bytes,
            self.now_us,
            false,
            false,
        );
        self.outbound_queue.push_back(OutboundLinkPacket {
            link_id,
            packet_number: pkt_num,
            meta,
            inner_frame_range,
            carries_ack: true,
            ack_eliciting: false,
            packet,
        });
        Ok(())
    }
}

struct VerifiedInitial {
    keys: EndpointKeys,
    local_dcid: ConnectionId,
    peer_dcid: ConnectionId,
    server_response: Option<(Option<ConnectionId>, Option<[u8; quic_base::INITIAL_VERIFIER_LEN]>)>,
}

fn shift_packet_right<P: PoolPacket>(packet: &mut P, shift: usize) -> Result<(), ()> {
    let r = packet.range();
    let slot = packet.slot_slice_mut().map_err(|_| ())?;
    if r.end + shift > slot.len() {
        return Err(());
    }
    slot.copy_within(r.start..r.end, r.start + shift);
    packet
        .set_range((r.start + shift)..(r.end + shift))
        .map_err(|_| ())
}

fn find_initial_crypto_params(wire: &[u8]) -> Result<Option<TransportParameters>, LinkRecvError> {
    let mut cursor = 0usize;
    while cursor < wire.len() {
        let (ty, n_ty) = decode_varint(&wire[cursor..]).map_err(LinkRecvError::Wire)?;
        match ty {
            FRAME_PADDING | FRAME_PING => cursor += n_ty,
            FRAME_CRYPTO => {
                let (offset, data_range, next_at) =
                    decode_crypto_frame_body(wire, cursor + n_ty).map_err(LinkRecvError::Wire)?;
                if offset == 0 {
                    let params = TransportParameters::decode(&wire[data_range])
                        .map_err(LinkRecvError::Wire)?;
                    return Ok(Some(params));
                }
                cursor = next_at;
            }
            FRAME_ACK => {
                let (_, _, _, next_at) =
                    decode_ack_frame_body(wire, cursor + n_ty).map_err(LinkRecvError::Wire)?;
                cursor = next_at;
            }
            FRAME_ACK_FREQUENCY => {
                let mut at = cursor + n_ty;
                for _ in 0..4 {
                    let (_, n) = decode_varint(
                        wire.get(at..)
                            .ok_or(LinkRecvError::Wire(WireError::UnexpectedEof))?,
                    )
                    .map_err(LinkRecvError::Wire)?;
                    at += n;
                }
                cursor = at;
            }
            FRAME_DATAGRAM => return Ok(None),
            FRAME_DATAGRAM_LEN => {
                let mut at = cursor + n_ty;
                let (l, nl) = decode_varint(
                    wire.get(at..)
                        .ok_or(LinkRecvError::Wire(WireError::UnexpectedEof))?,
                )
                .map_err(LinkRecvError::Wire)?;
                at += nl;
                let len =
                    usize::try_from(l).map_err(|_| LinkRecvError::Wire(WireError::InvalidFrame))?;
                cursor = at
                    .checked_add(len)
                    .ok_or(LinkRecvError::Wire(WireError::InvalidFrame))?;
            }
            _ => {
                let (_, rel_next) =
                    decode_frame(&wire[cursor..], 0).map_err(LinkRecvError::Wire)?;
                cursor += rel_next;
            }
        }
    }
    Ok(None)
}

impl<P: PoolPacket> AssociationEgress<P> for QuicLinkAssoc<P> {
    fn max_writable_frame_len(&self, assoc: AssociationId) -> usize {
        if assoc != self.config.assoc_id {
            return 0;
        }
        self.max_writable_len_for_priority(StreamPriority::CRITICAL)
    }

    fn send_packet(&mut self, meta: TxPacketMeta, packet: P) -> Result<(), LinkSendError<P>> {
        if meta.association != self.config.assoc_id {
            return Err(LinkSendError::NoAssociation(packet));
        }
        let frame_len = packet.bytes().len();
        let max_len = self.max_writable_len_for_priority(meta.priority);
        if max_len == 0 {
            return Err(LinkSendError::Busy(packet));
        }
        if frame_len > max_len {
            return Err(LinkSendError::TooLarge {
                packet,
                max_frame_len: max_len,
            });
        }
        let Some(link_id) =
            self.select_link(frame_len, meta.priority, meta.stream_id, None, false)
        else {
            return Err(LinkSendError::Busy(packet));
        };
        self.emit_on_link(link_id, meta, packet, true, false)
            .map_err(LinkSendError::Busy)
    }

    fn on_stream_aborted(&mut self, assoc: AssociationId, stream_id: StreamId) {
        if assoc == self.config.assoc_id {
            self.stream_affinity.remove(&stream_id);
            self.pending_retransmits
                .retain(|c| c.meta.stream_id != Some(stream_id));
            self.sack_ledger
                .purge_stream(assoc, stream_id, &mut self.links);
        }
    }

    fn drop_current_rx_ack(&mut self, assoc: AssociationId) {
        if assoc == self.config.assoc_id {
            if let Some(pn) = self.last_rx_pkt_num.take() {
                self.rx_ack_ranges.remove(pn);
            }
        }
    }
}

/// Callbacks for [`SingleStreamEndpoint`] (standalone single-stream + unreliable datagram mode
/// without `QuicMux`).
pub trait SingleStreamCallbacks<P: PoolPacket> {
    /// Deliver ordered stream payload bytes (`chunk.take_packet()` returns `Some(P)` for
    /// zero-copy single-stream packets).
    fn on_stream_data(&mut self, chunk: RxStreamChunk<'_, P>, fin: bool) -> RxOutcome<P>;

    /// Notify the consumer when [`SingleStreamEndpoint`] transitions to a new sequential `StreamId`.
    fn on_stream_reset(&mut self, _new_stream_id: StreamId) {}

    /// Deliver an incoming unreliable RFC 9221 `DATAGRAM` (`0x30` / `0x31`) with zero-copy
    /// ownership of `packet`.
    fn on_datagram(&mut self, _packet: P) {}
}

/// Configuration for [`SingleStreamEndpoint`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SingleStreamConfig {
    /// Fixed stream ID used for the single reliable stream (`StreamId(0)` by default).
    pub stream_id: StreamId,
    /// Priority assigned to the single reliable stream (`StreamPriority::NORMAL` by default).
    pub stream_priority: StreamPriority,
    /// Initial receive window (`MAX_DATA` / `MAX_STREAM_DATA`) in bytes.
    pub initial_recv_window: u64,
    /// Initial send window (`MAX_DATA` / `MAX_STREAM_DATA`) in bytes.
    pub initial_send_window: u64,
    /// Maximum out-of-order chunks buffered in [`OrderedStream`].
    pub max_reassembly_chunks: usize,
    /// Underlying association and link configuration.
    pub assoc: AssocConfig,
}

impl Default for SingleStreamConfig {
    fn default() -> Self {
        Self {
            stream_id: StreamId(0),
            stream_priority: StreamPriority::NORMAL,
            initial_recv_window: 64 * 1024,
            initial_send_window: 64 * 1024,
            max_reassembly_chunks: 32,
            assoc: AssocConfig::default(),
        }
    }
}

/// Standalone single-stream + unreliable `DATAGRAM` endpoint built directly on [`QuicLinkAssoc`]
/// **without** `QuicMux`.
///
/// Designed for ultra-low RAM/flash footprints when a single UDP or radio association only needs
/// one reliable bidirectional byte stream plus unreliable `DATAGRAM`s (`0x30`/`0x31`), while
/// still sharing `quic-mux`'s zero-copy `PoolPacket`, `OrderedStream<P>`, and flow-control
/// primitives.
pub struct SingleStreamEndpoint<Pool: PacketPool> {
    config: SingleStreamConfig,
    pool: Pool,
    assoc: QuicLinkAssoc<Pool::Packet>,
    send_fc: SendFlowControl,
    recv_fc: RecvFlowControl,
    send_offset: u64,
    fin_sent: bool,
    rx_stream: OrderedStream<Pool::Packet>,
}

impl<Pool: PacketPool> SingleStreamEndpoint<Pool> {
    /// Create a standalone single-stream endpoint with `pool` and `config`.
    pub fn new(pool: Pool, config: SingleStreamConfig) -> Self {
        let mut assoc = QuicLinkAssoc::new(config.assoc);
        assoc.set_advisory_available_conn_window(config.initial_send_window);
        Self {
            send_fc: SendFlowControl::new(config.initial_send_window),
            recv_fc: RecvFlowControl::new(config.initial_recv_window),
            send_offset: 0,
            fin_sent: false,
            rx_stream: OrderedStream::new(config.max_reassembly_chunks),
            assoc,
            pool,
            config,
        }
    }

    /// Borrow the underlying [`QuicLinkAssoc`].
    #[inline]
    pub const fn assoc(&self) -> &QuicLinkAssoc<Pool::Packet> {
        &self.assoc
    }

    /// Mutably borrow the underlying [`QuicLinkAssoc`].
    #[inline]
    pub fn assoc_mut(&mut self) -> &mut QuicLinkAssoc<Pool::Packet> {
        &mut self.assoc
    }

    /// Borrow the packet pool.
    #[inline]
    pub const fn pool(&self) -> &Pool {
        &self.pool
    }

    /// Mutably borrow the packet pool.
    #[inline]
    pub fn pool_mut(&mut self) -> &mut Pool {
        &mut self.pool
    }

    /// Allocate a `PoolPacket` from the endpoint's pool.
    #[inline]
    pub fn alloc_packet(&mut self) -> Result<Pool::Packet, PoolError> {
        self.pool.alloc()
    }

    /// Available send window bytes on the single reliable stream.
    #[inline]
    pub const fn available_send_window(&self) -> u64 {
        self.send_fc.available()
    }

    /// Currently active single stream ID.
    #[inline]
    pub const fn stream_id(&self) -> StreamId {
        self.config.stream_id
    }

    /// Whether the receive half of the current single stream has delivered `FIN`.
    #[inline]
    pub const fn is_rx_fin_delivered(&self) -> bool {
        self.rx_stream.is_fin_delivered()
    }

    /// Whether the send half of the current single stream has transmitted `FIN`.
    #[inline]
    pub const fn is_fin_sent(&self) -> bool {
        self.fin_sent
    }

    /// Reset the single stream's flow-control and reassembly state for a new sequential stream ID.
    pub fn reset_stream_state(&mut self, new_stream_id: StreamId) {
        let old_stream_id = self.config.stream_id;
        if old_stream_id != new_stream_id {
            self.assoc
                .on_stream_aborted(self.config.assoc.assoc_id, old_stream_id);
        }
        self.config.stream_id = new_stream_id;
        self.send_offset = 0;
        self.fin_sent = false;
        self.send_fc = SendFlowControl::new(self.config.initial_send_window);
        self.recv_fc = RecvFlowControl::new(self.config.initial_recv_window);
        self.rx_stream = OrderedStream::new(self.config.max_reassembly_chunks);
        self.assoc
            .set_advisory_available_conn_window(self.send_fc.available());
    }

    /// Maximum payload bytes that can currently be sent in a single `STREAM` frame.
    pub fn max_writable_payload_len(&self) -> usize {
        if !self.assoc.sack_ledger.can_admit(self.config.stream_priority) {
            return 0;
        }
        let fc_avail = usize::try_from(self.send_fc.available()).unwrap_or(usize::MAX);
        let max_frame = self
            .assoc
            .max_writable_len_for_priority(self.config.stream_priority);
        if max_frame <= 16 {
            return 0;
        }
        max_frame.saturating_sub(16).min(fc_avail)
    }

    /// Write a zero-copy `Pool::Packet` on the single reliable stream at `now_us`, returning the
    /// unmodified packet on `Err(pkt)` if flow control, congestion window, or SACK ledger capacity
    /// cannot currently admit it.
    pub fn write_stream_packet(
        &mut self,
        mut pkt: Pool::Packet,
        fin: bool,
        now_us: u64,
    ) -> Result<usize, Pool::Packet> {
        self.assoc.set_now_us(now_us);
        let payload_len = pkt.bytes().len();
        let max_payload = self.max_writable_payload_len();
        if (payload_len == 0 && !fin) || payload_len > max_payload {
            return Err(pkt);
        }
        let orig_range = pkt.range();
        let mut hdr_buf = [0u8; 24];
        let Ok(hdr_len) = encode_stream_header(
            self.config.stream_id,
            self.send_offset,
            payload_len,
            fin,
            true,
            &mut hdr_buf,
        ) else {
            return Err(pkt);
        };
        if pkt.prepend(&hdr_buf[..hdr_len]).is_err() {
            let _ = pkt.set_range(orig_range);
            return Err(pkt);
        }
        let meta = TxPacketMeta {
            association: self.config.assoc.assoc_id,
            stream_id: Some(self.config.stream_id),
            priority: self.config.stream_priority,
            retransmittable: true,
        };
        if let Err(err) = self.assoc.send_packet(meta, pkt) {
            let mut returned = match err {
                LinkSendError::Busy(p)
                | LinkSendError::TooLarge { packet: p, .. }
                | LinkSendError::NoAssociation(p) => p,
            };
            let _ = returned.set_range(orig_range);
            return Err(returned);
        }
        self.send_offset = self.send_offset.saturating_add(payload_len as u64);
        self.send_fc.commit_send(payload_len as u64);
        self.assoc
            .set_advisory_available_conn_window(self.send_fc.available());
        if fin {
            self.fin_sent = true;
        }
        Ok(payload_len)
    }

    /// Resume a paused receive stream after consumer backpressure clears, delivering any queued
    /// in-order chunks to `callbacks`.
    pub fn resume_stream<C: SingleStreamCallbacks<Pool::Packet>>(
        &mut self,
        consumed_from_paused: usize,
        now_us: u64,
        callbacks: &mut C,
    ) -> usize {
        self.assoc.set_now_us(now_us);
        self.rx_stream.clear_pause();
        if consumed_from_paused > 0 {
            self.recv_fc.on_consumed(consumed_from_paused as u64, true);
        }
        let mut delivered = 0usize;
        self.drain_reassembly_queue(now_us, callbacks, &mut delivered);
        self.maybe_emit_max_data();
        delivered
    }

    /// Credit `bytes` of consumed RX data and emit a `MAX_DATA` window update if threshold reached.
    pub fn credit_consumed_bytes(&mut self, bytes: usize, now_us: u64) {
        self.assoc.set_now_us(now_us);
        if bytes > 0 {
            self.recv_fc.on_consumed(bytes as u64, true);
        }
        self.maybe_emit_max_data();
    }

    /// Write reliable stream data (`TxStreamData::Packet` for zero-copy, or `TxStreamData::Bytes`)
    /// on the single stream at `now_us`.
    ///
    /// Returns `Ok(bytes_sent)` if admitted, or `Err( LinkSendError / PoolError )` if busy or
    /// flow-control limited.
    pub fn write_stream(
        &mut self,
        data: TxStreamData<'_, Pool::Packet>,
        fin: bool,
        now_us: u64,
    ) -> Result<usize, PoolError> {
        self.assoc.set_now_us(now_us);
        let payload_len = data.len();
        if payload_len as u64 > self.send_fc.available() {
            return Ok(0);
        }
        let max_frame = self
            .assoc
            .max_writable_len_for_priority(self.config.stream_priority);
        if max_frame <= 16 {
            return Ok(0);
        }
        let max_payload = max_frame.saturating_sub(16);
        if payload_len > max_payload {
            return Ok(0);
        }

        let mut pkt = match data {
            TxStreamData::Packet(p) => p,
            TxStreamData::Bytes(slice) => {
                let mut p = self.pool.alloc()?;
                p.append(slice)?;
                p
            }
        };

        let mut hdr_buf = [0u8; 24];
        let hdr_len = encode_stream_header(
            self.config.stream_id,
            self.send_offset,
            payload_len,
            fin,
            true,
            &mut hdr_buf,
        )
        .map_err(|_| PoolError::InvalidRange)?;
        pkt.prepend(&hdr_buf[..hdr_len])?;

        let meta = TxPacketMeta {
            association: self.config.assoc.assoc_id,
            stream_id: Some(self.config.stream_id),
            priority: self.config.stream_priority,
            retransmittable: true,
        };
        if self.assoc.send_packet(meta, pkt).is_err() {
            return Ok(0);
        }

        self.send_offset = self.send_offset.saturating_add(payload_len as u64);
        self.send_fc.commit_send(payload_len as u64);
        self.assoc
            .set_advisory_available_conn_window(self.send_fc.available());
        if fin {
            self.fin_sent = true;
        }
        Ok(payload_len)
    }

    /// Send an unreliable RFC 9221 `DATAGRAM` (`0x30` / `0x31`) over the standalone endpoint.
    pub fn send_datagram(
        &mut self,
        packet: Pool::Packet,
        priority: StreamPriority,
        now_us: u64,
    ) -> Result<LinkId, DatagramSendError<Pool::Packet>> {
        self.assoc.set_now_us(now_us);
        self.assoc
            .set_advisory_available_conn_window(self.send_fc.available());
        self.assoc.send_datagram(packet, priority)
    }

    /// Receive an incoming wire packet on `link_id` at `now_us`, dispatching any `DATAGRAM`s and
    /// ordered `STREAM` chunks to `callbacks`.
    pub fn receive_packet<C: SingleStreamCallbacks<Pool::Packet>>(
        &mut self,
        link_id: LinkId,
        packet: Pool::Packet,
        now_us: u64,
        callbacks: &mut C,
    ) -> Result<usize, LinkRecvError> {
        let outcome = self.assoc.receive_packet(link_id, packet, now_us)?;
        for dgram in outcome.datagrams {
            callbacks.on_datagram(dgram);
        }
        let mut delivered = 0usize;
        if let Some(mux_pkt) = outcome.mux_packet {
            delivered += self.process_inner_frames(mux_pkt, now_us, callbacks)?;
        }
        Ok(delivered)
    }

    /// Poll timers (delayed `ACK`, loss detection, PTO, and flow-control `MAX_DATA` updates) at `now_us`.
    pub fn poll_timers(&mut self, now_us: u64) -> usize {
        self.assoc.set_now_us(now_us);
        self.maybe_emit_max_data();
        self.assoc.poll_timers(&mut self.pool, now_us)
    }

    fn process_inner_frames<C: SingleStreamCallbacks<Pool::Packet>>(
        &mut self,
        mut packet: Pool::Packet,
        now_us: u64,
        callbacks: &mut C,
    ) -> Result<usize, LinkRecvError> {
        let base_range = packet.range();
        let total_len = packet.bytes().len();
        let mut cursor = 0usize;
        let mut stream_frames = Vec::new();

        while cursor < total_len {
            let (frame, next_at) =
                decode_frame(packet.bytes(), cursor).map_err(LinkRecvError::Wire)?;
            cursor = next_at;
            match frame {
                Frame::Padding | Frame::Ping => {}
                Frame::MaxData(max) => {
                    self.send_fc.update_peer_max(max);
                    self.assoc
                        .set_advisory_available_conn_window(self.send_fc.available());
                }
                Frame::MaxStreamData {
                    stream_id,
                    max_stream_data,
                } => {
                    if stream_id == self.config.stream_id {
                        self.send_fc.update_peer_max(max_stream_data);
                        self.assoc
                            .set_advisory_available_conn_window(self.send_fc.available());
                    }
                }
                Frame::Stream(sf) => {
                    if sf.stream_id < self.config.stream_id {
                        continue;
                    }
                    if sf.stream_id > self.config.stream_id
                        || (sf.offset == 0
                            && self.rx_stream.is_fin_delivered()
                            && self.fin_sent)
                    {
                        self.reset_stream_state(sf.stream_id);
                        callbacks.on_stream_reset(sf.stream_id);
                    }
                    if sf.stream_id == self.config.stream_id {
                        stream_frames.push(sf);
                    }
                }
                Frame::ResetStream { .. } | Frame::ConnectionClose { .. } => {
                    self.reset_stream_state(StreamId(0));
                }
                _ => {}
            }
        }

        let mut total_delivered = 0usize;
        let single_stream_frame = stream_frames.len() == 1;

        for sf in stream_frames {
            let payload_len = sf.payload_range.len() as u64;
            let end_offset = sf.offset.saturating_add(payload_len);
            if !self.recv_fc.on_receive_end(end_offset) {
                continue;
            }
            let abs_range =
                (base_range.start + sf.payload_range.start)..(base_range.start + sf.payload_range.end);

            if sf.offset == self.rx_stream.next_offset() && !self.rx_stream.is_paused() {
                if single_stream_frame {
                    let _ = packet.set_range(abs_range.clone());
                    let len = packet.bytes().len();
                    let res = callbacks.on_stream_data(RxStreamChunk::from_packet(packet), sf.fin);
                    match res {
                        RxOutcome::Consumed(n) => {
                            let consumed = n.min(len);
                            self.rx_stream
                                .advance_delivered(consumed, sf.fin && consumed == len, now_us);
                            self.recv_fc.on_consumed(consumed as u64, true);
                            total_delivered += consumed;
                            if consumed == len {
                                self.drain_reassembly_queue(now_us, callbacks, &mut total_delivered);
                            }
                        }
                        RxOutcome::Partial { consumed, packet } => {
                            let consumed = consumed.min(len);
                            self.rx_stream
                                .advance_delivered(consumed, sf.fin && consumed == len, now_us);
                            self.recv_fc.on_consumed(consumed as u64, true);
                            total_delivered += consumed;
                            if consumed < len {
                                let rem_range = (abs_range.start + consumed)..abs_range.end;
                                let _ = self.rx_stream.push_front_unconsumed(
                                    sf.offset + consumed as u64,
                                    packet,
                                    rem_range,
                                    sf.fin,
                                );
                            } else {
                                self.drain_reassembly_queue(now_us, callbacks, &mut total_delivered);
                            }
                        }
                        RxOutcome::RetainedPendingCredit => {
                            self.rx_stream.advance_delivered(len, sf.fin, now_us);
                            total_delivered += len;
                            self.drain_reassembly_queue(now_us, callbacks, &mut total_delivered);
                        }
                    }
                    self.maybe_emit_max_data();
                    return Ok(total_delivered);
                } else if let Ok(mut cloned) = packet.try_clone() {
                    let _ = cloned.set_range(abs_range.clone());
                    let _ = self
                        .rx_stream
                        .insert_out_of_order(sf.offset, cloned, abs_range, sf.fin, now_us);
                }
            } else if let Ok(cloned) = packet.try_clone() {
                let r = abs_range.clone();
                let _ = self
                    .rx_stream
                    .insert_out_of_order(sf.offset, cloned, r, sf.fin, now_us);
            }
        }

        self.drain_reassembly_queue(now_us, callbacks, &mut total_delivered);
        self.maybe_emit_max_data();
        Ok(total_delivered)
    }

    fn drain_reassembly_queue<C: SingleStreamCallbacks<Pool::Packet>>(
        &mut self,
        now_us: u64,
        callbacks: &mut C,
        total_delivered: &mut usize,
    ) {
        while let Some(chunk) = self.rx_stream.pop_next_in_order(now_us) {
            let len = chunk.payload.len();
            let fin = chunk.fin;
            let offset = chunk.offset;
            match chunk.payload {
                QueuedPayload::Packet(pkt) => {
                    let pkt_range = pkt.range();
                    let res = callbacks.on_stream_data(RxStreamChunk::from_packet(pkt), fin);
                    match res {
                        RxOutcome::Consumed(n) => {
                            let consumed = n.min(len);
                            self.rx_stream
                                .advance_delivered(consumed, fin && consumed == len, now_us);
                            self.recv_fc.on_consumed(consumed as u64, true);
                            *total_delivered += consumed;
                            if consumed < len {
                                break;
                            }
                        }
                        RxOutcome::Partial { consumed, packet } => {
                            let consumed = consumed.min(len);
                            self.rx_stream
                                .advance_delivered(consumed, fin && consumed == len, now_us);
                            self.recv_fc.on_consumed(consumed as u64, true);
                            *total_delivered += consumed;
                            if consumed < len {
                                let rem_range = (pkt_range.start + consumed)..pkt_range.end;
                                let _ = self.rx_stream.push_front_unconsumed(
                                    offset + consumed as u64,
                                    packet,
                                    rem_range,
                                    fin,
                                );
                                break;
                            }
                        }
                        RxOutcome::RetainedPendingCredit => {
                            self.rx_stream.advance_delivered(len, fin, now_us);
                            *total_delivered += len;
                        }
                    }
                }
                QueuedPayload::Small { data, range } => {
                    let slice = &data[range.clone()];
                    let res = callbacks.on_stream_data(RxStreamChunk::from_slice(slice), fin);
                    let consumed = match res {
                        RxOutcome::Consumed(n) => n.min(len),
                        RxOutcome::Partial { consumed, .. } => consumed.min(len),
                        RxOutcome::RetainedPendingCredit => len,
                    };
                    self.rx_stream
                        .advance_delivered(consumed, fin && consumed == len, now_us);
                    self.recv_fc.on_consumed(consumed as u64, true);
                    *total_delivered += consumed;
                    if consumed < len {
                        let _ = self.rx_stream.push_front_unconsumed_small(
                            offset + consumed as u64,
                            &slice[consumed..],
                            fin,
                        );
                        break;
                    }
                }
            }
        }
    }

    fn maybe_emit_max_data(&mut self) {
        if let Some(new_max) = self.recv_fc.peek_pending_update() {
            let Ok(mut pkt) = self.pool.alloc() else {
                return;
            };
            let mut buf = [0u8; 16];
            let Ok(n) = encode_control_frame(&Frame::MaxData(new_max), &mut buf) else {
                return;
            };
            if pkt.append(&buf[..n]).is_err() {
                return;
            }
            let meta = TxPacketMeta {
                association: self.config.assoc.assoc_id,
                stream_id: Some(self.config.stream_id),
                priority: StreamPriority::CRITICAL,
                retransmittable: true,
            };
            if self.assoc.send_packet(meta, pkt).is_ok() {
                self.recv_fc.clear_pending_update();
            }
        }
    }
}
