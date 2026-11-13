//! Comprehensive unit, multi-link simulation, and stress tests for `quic-link`.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use quic_mux::flow::{RxOutcome, StreamError};
use quic_mux::pool::{PacketPool, PoolPacket, XipLazyPacket, XipLazyPool};
use quic_mux::streams::{RxStreamChunk, TxStreamData};
use quic_mux::wire::StreamId;
use quic_mux::{
    AssociationEgress, AssociationId, MuxCallbacks, MuxLimits, MuxSendError, OWNER_ASSOC, QuicMux,
    RxMeta, StreamPriority, TxPacketMeta,
};

use crate::assoc::{
    AssocConfig, QuicLinkAssoc, SingleStreamCallbacks, SingleStreamConfig, SingleStreamEndpoint,
};
use crate::congestion::{LinkId, LinkProfile, LinkTxOutcome};
use crate::datagram::DatagramSendError;
use crate::sim::{SimLinkSpec, SimNetwork, SimSide};
use crate::wire::{
    ACK_RANGE_CAPACITY, AckRangeSet, ConnectionId, PacketAckRange, ShortHeader,
    decode_ack_frame_body, encode_ack_frame, packet_number_len,
};

// ============================================================================
// 1. Wire, ShortHeader Reconstruction, & AckRangeSet Tests
// ============================================================================

#[test]
fn connection_id_and_short_header_roundtrip_across_sizes() {
    for &raw_cid in &[
        0u64,
        1,
        127,
        128,
        0x1fff,
        0x2000,
        0x1fff_ffff,
        0x2000_0000,
        (1u64 << 60) + 99,
    ] {
        let cid = ConnectionId::new(raw_cid).unwrap();
        let mut buf = [0u8; 16];
        let n = cid.encode(&mut buf).unwrap();
        let (decoded, used) = ConnectionId::decode(&buf[..n]).unwrap();
        assert_eq!(n, used);
        assert_eq!(cid, decoded);
    }

    // Verify RFC 9000 packet-number truncation and sliding-window reconstruction across 1/2/3/4B boundaries.
    let cid = ConnectionId::new(7).unwrap();
    let cases = [
        (1u32, None, 1u32),
        (250, Some(200), 240),
        (260, Some(200), 255),
        (0x1_0005, Some(0x0fff0), 0x0ffff),
        (0x1234_5678, Some(0x1234_5600), 0x1234_5670),
        (0x7000_0010, Some(0x1000_0000), 0x6fff_ffff),
    ];
    for &(pn, largest_acked, expected_rx) in &cases {
        let pn_len = packet_number_len(pn, largest_acked);
        let hdr = ShortHeader {
            flags: 0,
            dcid: cid,
            packet_number: pn,
            packet_number_len: pn_len,
        };
        let mut wire = [0u8; ShortHeader::MAX_LEN];
        let encoded_len = hdr.encode(&mut wire).unwrap();
        let (reconstructed, used) =
            ShortHeader::decode_with_expected(&wire[..encoded_len], expected_rx).unwrap();
        assert_eq!(encoded_len, used);
        assert_eq!(reconstructed.dcid, cid);
        assert_eq!(reconstructed.packet_number, pn);
    }
}

#[test]
fn ack_range_set_merging_binary_search_and_eviction() {
    let mut ranges = AckRangeSet::new();
    // Insert 40 disjoint single-packet ranges (exceeding ACK_RANGE_CAPACITY = 32)
    for i in 0..40u32 {
        let pn = i * 3 + 1;
        ranges.insert(pn);
    }
    assert_eq!(ranges.len(), ACK_RANGE_CAPACITY);
    assert_eq!(ranges.largest(), Some(39 * 3 + 1));
    // Newest 32 disjoint ranges are kept; oldest 8 were evicted.
    assert!(ranges.contains(39 * 3 + 1));
    assert!(ranges.contains(8 * 3 + 1));
    assert!(!ranges.contains(7 * 3 + 1));

    // Merge adjacent ranges and round-trip through `encode_ack_frame` / `decode_ack_frame_body`.
    ranges.insert_range(PacketAckRange::new(100, 120));
    let mut buf = [0u8; 256];
    let n = encode_ack_frame(&ranges, 4_200, &mut buf).unwrap();
    assert_eq!(buf[0], 0x02);
    let (largest, delay, decoded, used) = decode_ack_frame_body(&buf, 1).unwrap();
    assert_eq!(used, n);
    assert_eq!(largest, ranges.largest().unwrap());
    assert_eq!(delay, 4_200);
    assert_eq!(decoded, ranges);
}

// ============================================================================
// 2. Multi-Link RTT Skew & Per-Link `send_order` SACK Loss Detection
// ============================================================================

#[test]
fn asymmetric_rtt_links_do_not_trigger_false_sack_losses() {
    let pool = XipLazyPool::with_default_geometry(128);
    let mut assoc = QuicLinkAssoc::<XipLazyPacket>::new(AssocConfig::default());

    let fast_udp = LinkId(1);
    let slow_ppp = LinkId(2);
    let cid = ConnectionId::new(1).unwrap();

    // Link 1: Fast UDP (tier 0, 5ms RTT)
    // Link 2: Slow PPP stream (tier 1, 100ms RTT)
    assoc.upsert_link(fast_udp, LinkProfile::udp_datagram(0, 1200, cid));
    let mut ppp_prof = LinkProfile::stream_link(1, 1200, 64 * 1024);
    ppp_prof.initial_rtt_us = 100_000;
    assoc.upsert_link(slow_ppp, ppp_prof);

    // Explicitly send 2 packets on slow_ppp (pn 1 and pn 2) by temporarily disabling fast_udp.
    assoc.link_mut(fast_udp).unwrap().enabled = false;
    for i in 0..2 {
        let mut pkt = pool.alloc().unwrap();
        pkt.append(&[0x08, 0x00, 0x02, 0x01, b'A' + i]).unwrap();
        assoc
            .send_packet(
                TxPacketMeta {
                    association: OWNER_ASSOC,
                    stream_id: Some(StreamId(0)),
                    priority: StreamPriority::NORMAL,
                    retransmittable: true,
                },
                pkt,
            )
            .unwrap();
    }
    assert_eq!(assoc.link(slow_ppp).unwrap().packets_in_flight, 2);

    // Re-enable fast_udp and send 10 packets on fast_udp (pn 3..=12) for a different stream (StreamId(8)).
    assoc.link_mut(fast_udp).unwrap().enabled = true;
    for i in 0..10u64 {
        assoc.set_now_us((i + 1) * 5_000);
        let mut pkt = pool.alloc().unwrap();
        pkt.append(&[0x08, 0x08, 0x02, 0x01, b'a' + (i as u8)])
            .unwrap();
        assoc
            .send_packet(
                TxPacketMeta {
                    association: OWNER_ASSOC,
                    stream_id: Some(StreamId(8)),
                    priority: StreamPriority::HIGH,
                    retransmittable: true,
                },
                pkt,
            )
            .unwrap();
    }
    assert_eq!(assoc.link(fast_udp).unwrap().packets_in_flight, 10);
    assert_eq!(assoc.link(slow_ppp).unwrap().packets_in_flight, 2);
    while assoc.pop_outbound_packet().is_some() {}

    // Now the peer ACKs pn 3..=12 (which arrived fast over UDP) while pn 1..=2 are still
    // in transit on the 100ms PPP link!
    let mut ack_set = AckRangeSet::new();
    ack_set.insert_range(PacketAckRange::new(3, 12));
    let mut rx_pkt = pool.alloc().unwrap();
    let mut ack_buf = [0u8; 64];
    let ack_len = encode_ack_frame(&ack_set, 500, &mut ack_buf).unwrap();
    rx_pkt.append(&ack_buf[..ack_len]).unwrap();
    let mut hdr_buf = [0u8; 16];
    let hdr_len = ShortHeader {
        flags: 0,
        dcid: cid,
        packet_number: 1,
        packet_number_len: 1,
    }
    .encode(&mut hdr_buf)
    .unwrap();
    rx_pkt.prepend(&hdr_buf[..hdr_len]).unwrap();

    let outcome = assoc.receive_packet(fast_udp, rx_pkt, 55_000).unwrap();
    assert_eq!(outcome.newly_acked_packets, 10);
    // CRITICAL ASSERTION: Even though pn 12 was ACKed and `1 + 3 <= 12` globally, pn 1 and pn 2
    // were sent on `slow_ppp` (where `largest_acked_send_order` is still `None`), so ZERO false
    // losses or retransmissions may be triggered!
    assert_eq!(
        outcome.retransmits_queued, 0,
        "fast UDP ACKs must not declare slow PPP packets lost"
    );
    assert_eq!(assoc.link(slow_ppp).unwrap().stats.packets_lost, 0);
    assert_eq!(assoc.link(slow_ppp).unwrap().packets_in_flight, 2);
}

// ============================================================================
// 3. LoRa / Multicast ESP-NOW Radio Mode (No MAC ACK, Priority Filter, Short Streams)
// ============================================================================

struct TestMuxReceiver {
    streams: BTreeMap<StreamId, Vec<u8>>,
    fins: BTreeMap<StreamId, bool>,
    datagrams: Vec<Vec<u8>>,
    zero_copy_packets_received: usize,
}

impl TestMuxReceiver {
    fn new() -> Self {
        Self {
            streams: BTreeMap::new(),
            fins: BTreeMap::new(),
            datagrams: Vec::new(),
            zero_copy_packets_received: 0,
        }
    }
}

impl MuxCallbacks<XipLazyPacket> for TestMuxReceiver {
    fn on_stream_data(
        &mut self,
        _assoc: AssociationId,
        stream_id: StreamId,
        _offset: u64,
        mut chunk: RxStreamChunk<'_, XipLazyPacket>,
        fin: bool,
    ) -> Result<RxOutcome<XipLazyPacket>, StreamError> {
        let len = chunk.len();
        let entry = self.streams.entry(stream_id).or_default();
        if let Some(pkt) = chunk.take_packet() {
            self.zero_copy_packets_received += 1;
            entry.extend_from_slice(pkt.bytes());
        } else {
            entry.extend_from_slice(chunk.bytes());
        }
        if fin {
            self.fins.insert(stream_id, true);
        }
        Ok(RxOutcome::Consumed(len))
    }
}

/// Drive a two-endpoint (`A` and `B`) `QuicMux` + `QuicLinkAssoc` simulation over `SimNetwork`.
#[allow(clippy::too_many_arguments)]
fn pump_mux_sim(
    net: &mut SimNetwork<XipLazyPacket>,
    mux_a: &mut QuicMux<XipLazyPool>,
    assoc_a: &mut QuicLinkAssoc<XipLazyPacket>,
    cb_a: &mut TestMuxReceiver,
    mux_b: &mut QuicMux<XipLazyPool>,
    assoc_b: &mut QuicLinkAssoc<XipLazyPacket>,
    cb_b: &mut TestMuxReceiver,
    step_us: u64,
    steps: usize,
) {
    for _ in 0..steps {
        let now = net.now_us() + step_us;
        assoc_a.set_now_us(now);
        assoc_b.set_now_us(now);

        // Poll timers on both sides
        let mut pool_a = mux_a.pool().clone();
        assoc_a.poll_timers(&mut pool_a, now);
        let _ = mux_a.advance_time(now, assoc_a, cb_a);

        let mut pool_b = mux_b.pool().clone();
        assoc_b.poll_timers(&mut pool_b, now);
        let _ = mux_b.advance_time(now, assoc_b, cb_b);

        // Enqueue outbound packets into the virtual network
        while let Some(out) = assoc_a.pop_outbound_packet() {
            net.transmit(SimSide::A, out.link_id, out.packet_number, out.packet);
        }
        while let Some(out) = assoc_b.pop_outbound_packet() {
            net.transmit(SimSide::B, out.link_id, out.packet_number, out.packet);
        }

        // Advance virtual network clock and process driver completions + packet deliveries
        let deliveries = net.step_to(now);
        for drv in net.drain_due_driver_events() {
            match drv.sender {
                SimSide::A => {
                    assoc_a.on_driver_complete(
                        drv.link_id,
                        drv.packet_number,
                        drv.outcome,
                        drv.completed_at_us,
                    );
                }
                SimSide::B => {
                    assoc_b.on_driver_complete(
                        drv.link_id,
                        drv.packet_number,
                        drv.outcome,
                        drv.completed_at_us,
                    );
                }
            }
        }

        for del in deliveries {
            match del.recipient {
                SimSide::A => {
                    if let Ok(outcome) =
                        assoc_a.receive_packet(del.link_id, del.packet, del.delivered_at_us)
                    {
                        for dg in outcome.datagrams {
                            cb_a.datagrams.push(dg.bytes().to_vec());
                        }
                        if let Some(mux_pkt) = outcome.mux_packet {
                            let _ = mux_a.receive_packet(
                                RxMeta {
                                    association: OWNER_ASSOC,
                                    received_at_us: del.delivered_at_us,
                                },
                                mux_pkt,
                                assoc_a,
                                cb_a,
                            );
                        }
                    }
                }
                SimSide::B => {
                    if let Ok(outcome) =
                        assoc_b.receive_packet(del.link_id, del.packet, del.delivered_at_us)
                    {
                        for dg in outcome.datagrams {
                            cb_b.datagrams.push(dg.bytes().to_vec());
                        }
                        if let Some(mux_pkt) = outcome.mux_packet {
                            let _ = mux_b.receive_packet(
                                RxMeta {
                                    association: OWNER_ASSOC,
                                    received_at_us: del.delivered_at_us,
                                },
                                mux_pkt,
                                assoc_b,
                                cb_b,
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn lora_and_multicast_espnow_without_mac_ack_completes_short_streams_and_blocks_bulk() {
    let pool_a = XipLazyPool::with_default_geometry(128);
    let pool_b = XipLazyPool::with_default_geometry(128);

    let mut mux_a = QuicMux::new(pool_a.clone(), MuxLimits::default());
    let mut mux_b = QuicMux::new(pool_b.clone(), MuxLimits::default());
    mux_a.add_association(OWNER_ASSOC, true).unwrap();
    mux_b.add_association(OWNER_ASSOC, false).unwrap();

    let mut assoc_a = QuicLinkAssoc::<XipLazyPacket>::new(AssocConfig::default());
    let mut assoc_b = QuicLinkAssoc::<XipLazyPacket>::new(AssocConfig::default());

    let lora_link = LinkId(10);
    let cid = ConnectionId::new(1).unwrap();
    // LoRa / Multicast ESP-NOW profile:
    // - max_priority = StreamPriority::NORMAL (blocks LOW and BULK!)
    // - max_inflight_packets = 4
    // - min_interval_us = 100_000 (100ms airtime pacing)
    // - min_pto_us = 450_000 (450ms PTO floor so we never retransmit while still in the air)
    let radio_prof = LinkProfile::radio_short_messages(3, 240, cid, 4, 100_000, 450_000);
    assoc_a.upsert_link(lora_link, radio_prof);
    assoc_b.upsert_link(lora_link, radio_prof);

    // Verify that `BULK` streams and `LOW` log datagrams are rejected when only the radio link is up!
    let bulk_sid = mux_a
        .open_stream_with_priority(OWNER_ASSOC, true, StreamPriority::BULK)
        .unwrap();
    let bulk_res = mux_a.write_stream(
        OWNER_ASSOC,
        bulk_sid,
        TxStreamData::Bytes(b"bulk firmware payload that must not clog LoRa"),
        false,
        &mut assoc_a,
    );
    assert!(
        matches!(bulk_res, Err(MuxSendError::Busy(_))),
        "BULK stream must be blocked from radio link with max_priority = NORMAL"
    );

    let mut low_dgram = pool_a.alloc().unwrap();
    low_dgram.append(b"low priority diagnostic log").unwrap();
    assert!(matches!(
        assoc_a.send_datagram(low_dgram, StreamPriority::LOW),
        Err(DatagramSendError::TooLarge { .. } | DatagramSendError::Busy(_))
    ));

    // Now simulate a 20% packet-loss LoRa / multicast ESP-NOW link WITHOUT L2 MAC ACKs (`has_mac_ack: false`).
    // Send 8 short messaging streams (1 packet each, `HIGH` and `NORMAL` priority) + high-priority datagrams.
    let mut net = SimNetwork::<XipLazyPacket>::new(0xBEEF_1234);
    net.add_link(SimLinkSpec::lora_no_mac_ack(lora_link, 2000)); // 20% loss in the air, no MAC ACK!

    let mut cb_a = TestMuxReceiver::new();
    let mut cb_b = TestMuxReceiver::new();

    let mut expected_messages: BTreeMap<StreamId, Vec<u8>> = BTreeMap::new();
    for msg_idx in 0..8u8 {
        let prio = if msg_idx % 2 == 0 {
            StreamPriority::HIGH
        } else {
            StreamPriority::NORMAL
        };
        let sid = mux_a
            .open_stream_with_priority(OWNER_ASSOC, true, prio)
            .unwrap();
        let msg = vec![b'M' + msg_idx; 140]; // fits in 1 LoRa packet with headers
        expected_messages.insert(sid, msg.clone());

        // Pump until the radio airtime pacer admits this short stream message
        let mut sent = false;
        for _ in 0..120 {
            let now = net.now_us();
            assoc_a.set_now_us(now);
            if mux_a
                .write_stream(
                    OWNER_ASSOC,
                    sid,
                    TxStreamData::Bytes(&msg),
                    true, // short message stream closes with FIN immediately!
                    &mut assoc_a,
                )
                .is_ok()
            {
                sent = true;
                break;
            }
            pump_mux_sim(
                &mut net,
                &mut mux_a,
                &mut assoc_a,
                &mut cb_a,
                &mut mux_b,
                &mut assoc_b,
                &mut cb_b,
                25_000,
                2,
            );
        }
        assert!(sent, "short message {msg_idx} should be admitted onto LoRa");
    }

    // Also send a HIGH-priority unreliable datagram from B -> A so B piggybacks ACKs onto its traffic!
    let mut hi_dgram = pool_b.alloc().unwrap();
    hi_dgram.append(b"urgent beacon over LoRa").unwrap();
    let _ = assoc_b.send_datagram(hi_dgram, StreamPriority::HIGH);

    // Run virtual time forward (up to 15 seconds of simulated radio time in 25ms ticks) so all
    // 20%-dropped packets recover via SACK / PTO over the no-MAC-ACK LoRa link.
    pump_mux_sim(
        &mut net,
        &mut mux_a,
        &mut assoc_a,
        &mut cb_a,
        &mut mux_b,
        &mut assoc_b,
        &mut cb_b,
        25_000,
        600,
    );

    for (sid, expected) in &expected_messages {
        assert_eq!(
            cb_b.streams.get(sid),
            Some(expected),
            "short radio stream {sid:?} did not arrive intact over 20%-loss no-MAC-ACK LoRa"
        );
        assert_eq!(cb_b.fins.get(sid), Some(&true));
    }
    let (tx_cnt, drop_cnt) = net.link_counters(lora_link).unwrap();
    assert!(
        drop_cnt > 0,
        "expected real air drops during 20% loss LoRa simulation (tx={tx_cnt})"
    );
    assert!(
        assoc_a.link(lora_link).unwrap().stats.retransmissions_sent > 0,
        "expected SACK/PTO retransmissions to recover air-dropped LoRa packets"
    );
}

// ============================================================================
// 4. Mid-Flight Link Failure & Zero-Copy Cross-Link Failover (TCP -> UDP/Radio)
// ============================================================================

#[test]
fn mid_flight_tcp_link_failure_evacuates_and_retransmits_over_backup_udp_link() {
    let pool_a = XipLazyPool::with_default_geometry(128);
    let pool_b = XipLazyPool::with_default_geometry(128);

    let mut mux_a = QuicMux::new(pool_a.clone(), MuxLimits::default());
    let mut mux_b = QuicMux::new(pool_b.clone(), MuxLimits::default());
    mux_a.add_association(OWNER_ASSOC, true).unwrap();
    mux_b.add_association(OWNER_ASSOC, false).unwrap();

    let mut assoc_a = QuicLinkAssoc::<XipLazyPacket>::new(AssocConfig::default());
    let mut assoc_b = QuicLinkAssoc::<XipLazyPacket>::new(AssocConfig::default());

    let tcp_link = LinkId(1);
    let udp_backup = LinkId(2);
    let cid = ConnectionId::new(1).unwrap();

    // Link 1: Primary TCP/stream link (tier 0, SelfDelimitingStream framing)
    // Link 2: Backup UDP datagram link (tier 1, Datagram framing)
    assoc_a.upsert_link(tcp_link, LinkProfile::stream_link(0, 1200, 64 * 1024));
    assoc_a.upsert_link(udp_backup, LinkProfile::udp_datagram(1, 1200, cid));
    assoc_b.upsert_link(tcp_link, LinkProfile::stream_link(0, 1200, 64 * 1024));
    assoc_b.upsert_link(udp_backup, LinkProfile::udp_datagram(1, 1200, cid));

    let sid = mux_a
        .open_stream_with_priority(OWNER_ASSOC, true, StreamPriority::HIGH)
        .unwrap();
    let payload = vec![0x5Au8; 4_000];
    let mut offset = 0;
    while offset < payload.len() {
        let end = (offset + 800).min(payload.len());
        let fin = end == payload.len();
        let written = mux_a
            .write_stream(
                OWNER_ASSOC,
                sid,
                TxStreamData::Bytes(&payload[offset..end]),
                fin,
                &mut assoc_a,
            )
            .unwrap();
        offset += written;
    }

    // All 5 initial packets must have been scheduled on `tcp_link` (tier 0).
    assert_eq!(assoc_a.link(tcp_link).unwrap().stats.packets_sent, 5);
    assert_eq!(assoc_a.link(udp_backup).unwrap().stats.packets_sent, 0);

    // Simulate the TCP link breaking while the last 3 packets are in flight (only deliver the first 2)!
    let mut net = SimNetwork::<XipLazyPacket>::new(0x1234_5678);
    net.add_link(SimLinkSpec::fast_udp(tcp_link));
    net.add_link(SimLinkSpec::fast_udp(udp_backup));

    let mut idx = 0;
    while let Some(out) = assoc_a.pop_outbound_packet() {
        if idx < 2 {
            net.transmit(SimSide::A, out.link_id, out.packet_number, out.packet);
        }
        // Packets 2, 3, 4 are blackholed when TCP dies before delivery!
        idx += 1;
    }

    let mut cb_a = TestMuxReceiver::new();
    let mut cb_b = TestMuxReceiver::new();

    // Deliver the first 2 packets to B.
    pump_mux_sim(
        &mut net,
        &mut mux_a,
        &mut assoc_a,
        &mut cb_a,
        &mut mux_b,
        &mut assoc_b,
        &mut cb_b,
        5_000,
        3,
    );

    // Now mark `tcp_link` failed on A (`fail_link`)!
    // The remaining unACKed packets on `tcp_link` must be evacuated and immediately reframed with
    // fresh packet numbers onto `udp_backup` with zero payload copies.
    let evacuated = assoc_a.fail_link(tcp_link, false, net.now_us());
    assert!(evacuated >= 3, "expected at least 3 unACKed packets evacuated from failed tcp_link");
    assert!(
        assoc_a.link(udp_backup).unwrap().stats.retransmissions_sent >= 3,
        "evacuated packets should immediately retransmit on udp_backup"
    );

    // Pump the network and verify B receives the entire 4,000-byte stream seamlessly!
    pump_mux_sim(
        &mut net,
        &mut mux_a,
        &mut assoc_a,
        &mut cb_a,
        &mut mux_b,
        &mut assoc_b,
        &mut cb_b,
        5_000,
        10,
    );

    assert_eq!(cb_b.streams.get(&sid), Some(&payload));
    assert_eq!(cb_b.fins.get(&sid), Some(&true));
}

// ============================================================================
// 5. Unreliable DATAGRAM (`0x30`/`0x31`) Zero-Copy & Low-Priority Window Shedding
// ============================================================================

#[test]
fn unreliable_datagram_zero_copy_and_low_priority_shedding() {
    let pool = XipLazyPool::with_default_geometry(64);
    let mut assoc_a = QuicLinkAssoc::<XipLazyPacket>::new(AssocConfig::default());
    let mut assoc_b = QuicLinkAssoc::<XipLazyPacket>::new(AssocConfig::default());

    let udp_link = LinkId(1);
    let tcp_link = LinkId(2);
    let cid = ConnectionId::new(1).unwrap();

    assoc_a.upsert_link(udp_link, LinkProfile::udp_datagram(0, 1200, cid));
    assoc_b.upsert_link(udp_link, LinkProfile::udp_datagram(0, 1200, cid));

    // 1. Send a HIGH-priority datagram on UDP (`0x30` framing without explicit length).
    let mut dg1 = pool.alloc().unwrap();
    dg1.append(b"high-priority sensor telemetry").unwrap();
    let used_link = assoc_a.send_datagram(dg1, StreamPriority::HIGH).unwrap();
    assert_eq!(used_link, udp_link);
    assert_eq!(
        assoc_a.sack_ledger().retained_packets(),
        0,
        "unreliable DATAGRAM must never retain a PoolPacket lease in the SACK ledger"
    );

    let out1 = assoc_a.pop_outbound_packet().unwrap();
    let demux1 = assoc_b
        .receive_packet(udp_link, out1.packet, 1_000)
        .unwrap();
    assert_eq!(demux1.datagrams.len(), 1);
    assert!(
        demux1.datagrams[0].is_unique(),
        "extracted single DATAGRAM PoolPacket must be uniquely owned for zero-copy consumers"
    );
    assert_eq!(demux1.datagrams[0].bytes(), b"high-priority sensor telemetry");

    // 2. When advisory connection window is tight (`< low_priority_window_reserve_bytes`),
    //    `LOW` and `BULK` datagrams are shed while `NORMAL` and `HIGH` still pass!
    assoc_a.set_advisory_available_conn_window(500); // below 1200 reserve
    let mut low_dg = pool.alloc().unwrap();
    low_dg.append(b"background debug log line").unwrap();
    let err = assoc_a
        .send_datagram(low_dg, StreamPriority::LOW)
        .expect_err("LOW datagram must be shed when advisory window is tight");
    assert!(matches!(err, DatagramSendError::LowPriorityShed(_)));

    let mut norm_dg = pool.alloc().unwrap();
    norm_dg.append(b"normal control datagram").unwrap();
    assert!(assoc_a.send_datagram(norm_dg, StreamPriority::NORMAL).is_ok());
    let _ = assoc_a.pop_outbound_packet();

    // 3. On a `SelfDelimitingStream` link (TCP/PPP), `send_datagram` automatically uses `0x31`
    //    (`FRAME_DATAGRAM_LEN`) so frames are self-delimited on the byte stream.
    assoc_a.link_mut(udp_link).unwrap().enabled = false;
    assoc_a.upsert_link(tcp_link, LinkProfile::stream_link(1, 1200, 64 * 1024));
    assoc_b.upsert_link(tcp_link, LinkProfile::stream_link(1, 1200, 64 * 1024));

    let mut stream_dg = pool.alloc().unwrap();
    stream_dg.append(b"self-delimited datagram on TCP").unwrap();
    assert_eq!(
        assoc_a.send_datagram(stream_dg, StreamPriority::HIGH).unwrap(),
        tcp_link
    );
    let out_tcp = assoc_a.pop_outbound_packet().unwrap();
    let demux_tcp = assoc_b
        .receive_packet(tcp_link, out_tcp.packet, 2_000)
        .unwrap();
    assert_eq!(demux_tcp.datagrams.len(), 1);
    assert_eq!(
        demux_tcp.datagrams[0].bytes(),
        b"self-delimited datagram on TCP"
    );
}

// ============================================================================
// 6. Dynamic Memory Pressure Eviction in `MultiLinkSackLedger`
// ============================================================================

#[test]
fn sack_ledger_evicts_lowest_priority_streams_first_under_memory_pressure() {
    let pool = XipLazyPool::with_default_geometry(64);
    let mut cfg = AssocConfig::default();
    cfg.max_retained_tx_packets = 6;
    let mut assoc = QuicLinkAssoc::<XipLazyPacket>::new(cfg);

    let cid = ConnectionId::new(1).unwrap();
    assoc.upsert_link(
        LinkId(1),
        LinkProfile::stream_link(0, 1200, 256 * 1024),
    );
    let _ = cid;

    let crit_stream = StreamId(0);
    let bulk_stream = StreamId(4);
    let low_stream = StreamId(8);

    // Send 2 CRITICAL packets, 2 LOW packets, and 2 BULK packets (filling all 6 retained slots).
    for &(sid, prio) in &[
        (crit_stream, StreamPriority::CRITICAL),
        (crit_stream, StreamPriority::CRITICAL),
        (low_stream, StreamPriority::LOW),
        (low_stream, StreamPriority::LOW),
        (bulk_stream, StreamPriority::BULK),
        (bulk_stream, StreamPriority::BULK),
    ] {
        let mut pkt = pool.alloc().unwrap();
        pkt.append(&[0x08, sid.0 as u8, 0x02, 0x01, 0xAA]).unwrap();
        assoc
            .send_packet(
                TxPacketMeta {
                    association: OWNER_ASSOC,
                    stream_id: Some(sid),
                    priority: prio,
                    retransmittable: true,
                },
                pkt,
            )
            .unwrap();
    }
    assert_eq!(assoc.sack_ledger().retained_packets(), 6);

    // Sending a HIGH-priority packet when the 6-slot ledger is full must automatically evict
    // `bulk_stream` (`StreamPriority::BULK`) and succeed!
    let mut hi_pkt = pool.alloc().unwrap();
    hi_pkt.append(&[0x08, 0x0c, 0x02, 0x01, 0xBB]).unwrap();
    assoc
        .send_packet(
            TxPacketMeta {
                association: OWNER_ASSOC,
                stream_id: Some(StreamId(12)),
                priority: StreamPriority::HIGH,
                retransmittable: true,
            },
            hi_pkt,
        )
        .unwrap();
    let evicted = assoc.take_evicted_streams();
    assert_eq!(evicted, vec![(OWNER_ASSOC, bulk_stream)]);
    assert_eq!(assoc.sack_ledger().retained_packets(), 5);

    // Dynamically shrinking `max_retained_tx_packets` to 3 under system RAM pressure must evict
    // `low_stream` (`StreamPriority::LOW`) while preserving `crit_stream` and `StreamId(12)`!
    let evicted2 = assoc.set_max_retained_tx_packets(3);
    assert_eq!(evicted2, vec![(OWNER_ASSOC, low_stream)]);
    assert_eq!(assoc.sack_ledger().retained_packets(), 3);
}

// ============================================================================
// 7. Standalone `SingleStreamEndpoint` (No `QuicMux`) Under Loss & Reordering
// ============================================================================

struct TestSingleReceiver {
    received: Vec<u8>,
    fin: bool,
    datagrams: Vec<Vec<u8>>,
    zero_copy_chunks: usize,
}

impl TestSingleReceiver {
    fn new() -> Self {
        Self {
            received: Vec::new(),
            fin: false,
            datagrams: Vec::new(),
            zero_copy_chunks: 0,
        }
    }
}

impl SingleStreamCallbacks<XipLazyPacket> for TestSingleReceiver {
    fn on_stream_data(
        &mut self,
        mut chunk: RxStreamChunk<'_, XipLazyPacket>,
        fin: bool,
    ) -> RxOutcome<XipLazyPacket> {
        let len = chunk.len();
        if let Some(pkt) = chunk.take_packet() {
            self.zero_copy_chunks += 1;
            self.received.extend_from_slice(pkt.bytes());
        } else {
            self.received.extend_from_slice(chunk.bytes());
        }
        if fin {
            self.fin = true;
        }
        RxOutcome::Consumed(len)
    }

    fn on_datagram(&mut self, packet: XipLazyPacket) {
        self.datagrams.push(packet.bytes().to_vec());
    }
}

#[test]
fn standalone_single_stream_endpoint_transfers_256kib_plus_datagrams_under_loss_and_jitter() {
    let pool_a = XipLazyPool::with_default_geometry(128);
    let pool_b = XipLazyPool::with_default_geometry(128);

    let mut cfg = SingleStreamConfig::default();
    cfg.initial_recv_window = 64 * 1024;
    cfg.initial_send_window = 64 * 1024;
    cfg.max_reassembly_chunks = 64;
    cfg.assoc.max_retained_tx_packets = 64;

    let mut ep_a = SingleStreamEndpoint::new(pool_a, cfg);
    let mut ep_b = SingleStreamEndpoint::new(pool_b, cfg);

    let udp_link = LinkId(1);
    let cid = ConnectionId::new(1).unwrap();
    let mut prof = LinkProfile::udp_datagram(0, 1200, cid);
    prof.congestion_mode = crate::congestion::CongestionMode::NewRenoPaced {
        initial_window_bytes: 32 * 1024,
        pacing: crate::congestion::PacingConfig::disabled(1200),
    };
    ep_a.assoc_mut().upsert_link(udp_link, prof);
    ep_b.assoc_mut().upsert_link(udp_link, prof);

    // Simulate a UDP link with 8% packet loss and 4ms jitter (causing both loss and out-of-order arrival!).
    let mut net = SimNetwork::<XipLazyPacket>::new(0xCAFE_F00D);
    let mut spec = SimLinkSpec::fast_udp(udp_link);
    spec.loss_ppm_10k = 800; // 8% packet loss
    spec.jitter_us = 4_000; // 4ms jitter -> packet reordering
    net.add_link(spec);

    // Prepare 256 KiB payload (4x the initial 64 KiB flow-control window, exercising `MAX_DATA` updates!).
    let total_size = 256 * 1024;
    let mut expected = Vec::with_capacity(total_size);
    for i in 0..total_size {
        expected.push(((i * 31 + 7) & 0xff) as u8);
    }

    let mut cb_a = TestSingleReceiver::new();
    let mut cb_b = TestSingleReceiver::new();

    // Also send a zero-copy datagram from A -> B.
    let mut dg = ep_a.alloc_packet().unwrap();
    dg.append(b"standalone-mode-datagram").unwrap();
    ep_a.send_datagram(dg, StreamPriority::HIGH, 0).unwrap();

    let mut sent_offset = 0usize;
    for tick in 0..4_000usize {
        let now = (tick as u64 + 1) * 2_000; // 2ms ticks

        // Push more stream chunks from A whenever flow control and congestion window allow.
        while sent_offset < expected.len() {
            let chunk_len = (expected.len() - sent_offset).min(1000);
            let fin = sent_offset + chunk_len == expected.len();
            // Exercise zero-copy `TxStreamData::Packet` on even chunks and `TxStreamData::Bytes` on odd chunks.
            let res = if (sent_offset / 1000) % 2 == 0 {
                let Ok(mut pkt) = ep_a.alloc_packet() else {
                    break;
                };
                pkt.append(&expected[sent_offset..sent_offset + chunk_len])
                    .unwrap();
                ep_a.write_stream(TxStreamData::Packet(pkt), fin, now)
            } else {
                ep_a.write_stream(
                    TxStreamData::Bytes(&expected[sent_offset..sent_offset + chunk_len]),
                    fin,
                    now,
                )
            };
            match res {
                Ok(n) if n > 0 => {
                    sent_offset += n;
                }
                _ => break,
            }
        }

        ep_a.poll_timers(now);
        ep_b.poll_timers(now);

        while let Some(out) = ep_a.assoc_mut().pop_outbound_packet() {
            net.transmit(SimSide::A, out.link_id, out.packet_number, out.packet);
        }
        while let Some(out) = ep_b.assoc_mut().pop_outbound_packet() {
            net.transmit(SimSide::B, out.link_id, out.packet_number, out.packet);
        }

        let deliveries = net.step_to(now);
        for drv in net.drain_due_driver_events() {
            match drv.sender {
                SimSide::A => {
                    ep_a.assoc_mut().on_driver_complete(
                        drv.link_id,
                        drv.packet_number,
                        drv.outcome,
                        drv.completed_at_us,
                    );
                }
                SimSide::B => {
                    ep_b.assoc_mut().on_driver_complete(
                        drv.link_id,
                        drv.packet_number,
                        drv.outcome,
                        drv.completed_at_us,
                    );
                }
            }
        }

        for del in deliveries {
            match del.recipient {
                SimSide::A => {
                    let _ = ep_a.receive_packet(
                        del.link_id,
                        del.packet,
                        del.delivered_at_us,
                        &mut cb_a,
                    );
                }
                SimSide::B => {
                    let _ = ep_b.receive_packet(
                        del.link_id,
                        del.packet,
                        del.delivered_at_us,
                        &mut cb_b,
                    );
                }
            }
        }

        if cb_b.fin && cb_b.received.len() == expected.len() {
            break;
        }
    }

    assert_eq!(cb_b.received.len(), expected.len());
    assert_eq!(cb_b.received, expected);
    assert!(cb_b.fin);
    assert!(
        cb_b.zero_copy_chunks > 100,
        "expected zero-copy PoolPacket handoff in SingleStreamEndpoint (got {})",
        cb_b.zero_copy_chunks
    );
}

// ============================================================================
// 8. Heterogeneous 3-Link Stress Test (UDP + Slow PPP + No-MAC-ACK LoRa)
//    & Spurious Loss Adaptation
// ============================================================================

#[test]
fn heterogeneous_three_link_stress_test_and_spurious_loss_adaptation() {
    let pool_a = XipLazyPool::with_default_geometry(256);
    let pool_b = XipLazyPool::with_default_geometry(256);

    let mut limits = MuxLimits::default();
    limits.initial_max_data = 256 * 1024;
    limits.initial_max_stream_data = 64 * 1024;
    limits.max_queued_chunks_per_stream = 64;
    limits.max_association_rx_packets = 128;
    limits.max_device_rx_packets = 128;

    let mut mux_a = QuicMux::new(pool_a.clone(), limits);
    let mut mux_b = QuicMux::new(pool_b.clone(), limits);
    mux_a.add_association(OWNER_ASSOC, true).unwrap();
    mux_b.add_association(OWNER_ASSOC, false).unwrap();

    let mut assoc_cfg = AssocConfig::default();
    assoc_cfg.max_retained_tx_packets = 128;
    let mut assoc_a = QuicLinkAssoc::<XipLazyPacket>::new(assoc_cfg);
    let mut assoc_b = QuicLinkAssoc::<XipLazyPacket>::new(assoc_cfg);

    let udp_link = LinkId(1);
    let ppp_link = LinkId(2);
    let lora_link = LinkId(3);
    let cid = ConnectionId::new(1).unwrap();

    // Link 1: Tier 0 UDP (fast 5ms, admits up to BULK)
    // Link 2: Tier 1 PPP stream (80ms, admits up to BULK)
    // Link 3: Tier 2 LoRa no-MAC-ACK radio (120ms, admits only up to NORMAL!)
    let mut udp_prof = LinkProfile::udp_datagram(0, 1200, cid);
    udp_prof.congestion_mode = crate::congestion::CongestionMode::NewRenoPaced {
        initial_window_bytes: 24 * 1024,
        pacing: crate::congestion::PacingConfig::disabled(1200),
    };
    assoc_a.upsert_link(udp_link, udp_prof);
    assoc_b.upsert_link(udp_link, udp_prof);

    assoc_a.upsert_link(ppp_link, LinkProfile::stream_link(1, 1200, 32 * 1024));
    assoc_b.upsert_link(ppp_link, LinkProfile::stream_link(1, 1200, 32 * 1024));

    let radio_prof = LinkProfile::radio_short_messages(2, 240, cid, 4, 80_000, 400_000);
    assoc_a.upsert_link(lora_link, radio_prof);
    assoc_b.upsert_link(lora_link, radio_prof);

    let mut net = SimNetwork::<XipLazyPacket>::new(0x7777_8888);
    let mut udp_spec = SimLinkSpec::fast_udp(udp_link);
    udp_spec.loss_ppm_10k = 1000; // 10% loss on UDP
    udp_spec.loss_burst_len = 2; // burst loss of 2 packets
    udp_spec.jitter_us = 3_000;
    net.add_link(udp_spec);

    let mut ppp_spec = SimLinkSpec::slow_ppp(ppp_link);
    ppp_spec.loss_ppm_10k = 300; // 3% loss on PPP
    net.add_link(ppp_spec);

    net.add_link(SimLinkSpec::lora_no_mac_ack(lora_link, 1000)); // 10% loss on LoRa

    // Open:
    // - 2 CRITICAL short command streams (300 bytes each)
    // - 2 HIGH interactive streams (4 KiB each)
    // - 2 BULK transfer streams (24 KiB each)
    let mut streams_to_send: Vec<(StreamId, Vec<u8>, usize)> = Vec::new();
    for i in 0..2u8 {
        let sid = mux_a
            .open_stream_with_priority(OWNER_ASSOC, true, StreamPriority::CRITICAL)
            .unwrap();
        streams_to_send.push((sid, vec![0xC0 + i; 300], 0));
    }
    for i in 0..2u8 {
        let sid = mux_a
            .open_stream_with_priority(OWNER_ASSOC, true, StreamPriority::HIGH)
            .unwrap();
        streams_to_send.push((sid, vec![0xA0 + i; 4_096], 0));
    }
    for i in 0..2u8 {
        let sid = mux_a
            .open_stream_with_priority(OWNER_ASSOC, true, StreamPriority::BULK)
            .unwrap();
        streams_to_send.push((sid, vec![0xB0 + i; 24_576], 0));
    }

    let mut cb_a = TestMuxReceiver::new();
    let mut cb_b = TestMuxReceiver::new();

    for tick in 0..2_500usize {
        let now = net.now_us();
        assoc_a.set_now_us(now);

        // Midway through (tick 200..400), simulate UDP blackout so traffic fails over to PPP + LoRa,
        // and then restore UDP at tick 400!
        if tick == 200 {
            net.link_spec_mut(udp_link).unwrap().up = false;
            assoc_a.fail_link(udp_link, false, now);
        } else if tick == 400 {
            net.link_spec_mut(udp_link).unwrap().up = true;
            if let Some(l) = assoc_a.link_mut(udp_link) {
                l.enabled = true;
                l.driver_ready = true;
            }
        }

        for (sid, data, offset) in &mut streams_to_send {
            while *offset < data.len() {
                let max_chunk = if assoc_a.link(udp_link).unwrap().enabled {
                    900
                } else {
                    180
                };
                let chunk = (data.len() - *offset).min(max_chunk);
                let fin = *offset + chunk == data.len();
                match mux_a.write_stream(
                    OWNER_ASSOC,
                    *sid,
                    TxStreamData::Bytes(&data[*offset..*offset + chunk]),
                    fin,
                    &mut assoc_a,
                ) {
                    Ok(n) if n > 0 => *offset += n,
                    _ => break,
                }
            }
        }

        pump_mux_sim(
            &mut net,
            &mut mux_a,
            &mut assoc_a,
            &mut cb_a,
            &mut mux_b,
            &mut assoc_b,
            &mut cb_b,
            5_000,
            1,
        );

        let all_done = streams_to_send
            .iter()
            .all(|(sid, data, _)| cb_b.fins.get(sid) == Some(&true) && cb_b.streams.get(sid) == Some(data));
        if all_done {
            break;
        }
    }

    for (sid, expected, _) in &streams_to_send {
        assert_eq!(
            cb_b.streams.get(sid).map(Vec::len),
            Some(expected.len()),
            "stream {sid:?} incomplete after 3-link heterogeneous stress test"
        );
        assert_eq!(cb_b.streams.get(sid), Some(expected));
        assert_eq!(cb_b.fins.get(sid), Some(&true));
    }

    // Also verify driver-level `LinkTxOutcome::Failed` handling and spurious-loss threshold adaptation.
    let mut assoc_spurious = QuicLinkAssoc::<XipLazyPacket>::new(AssocConfig::default());
    assoc_spurious.upsert_link(udp_link, LinkProfile::udp_datagram(0, 1200, cid));
    for i in 0..5u8 {
        let mut p = pool_a.alloc().unwrap();
        p.append(&[0x08, 0x00, 0x02, 0x01, i]).unwrap();
        assoc_spurious
            .send_packet(
                TxPacketMeta {
                    association: OWNER_ASSOC,
                    stream_id: Some(StreamId(0)),
                    priority: StreamPriority::HIGH,
                    retransmittable: true,
                },
                p,
            )
            .unwrap();
    }
    // Simulate driver failure on pn 1 -> immediately queued for failover without halving cwnd.
    let initial_cwnd = assoc_spurious.link(udp_link).unwrap().congestion.congestion_window;
    assert!(assoc_spurious.on_driver_complete(udp_link, 1, LinkTxOutcome::Failed, 1_000));
    assert_eq!(
        assoc_spurious.link(udp_link).unwrap().congestion.congestion_window,
        initial_cwnd,
        "local driver Failed outcome must not halve NewReno cwnd"
    );
}

#[cfg(feature = "stateless-reset")]
#[test]
fn stateless_reset_key_derives_and_matches_token_on_unknown_cid() {
    use crate::{STATELESS_RESET_MIN_PACKET_LEN, StatelessResetKey};

    let key = StatelessResetKey::from_device_secret(&[0x3c; 32]).unwrap();
    let unknown_cid = ConnectionId::new(0x1020).unwrap();
    let other_cid = ConnectionId::new(0x3040).unwrap();
    let token = key.token_for(unknown_cid);
    let other_token = key.token_for(other_cid);
    assert_ne!(token, other_token);

    let mut triggering = [0u8; 32];
    let hdr = ShortHeader {
        flags: 0x40,
        dcid: unknown_cid,
        packet_number: 7,
        packet_number_len: 1,
    };
    let hdr_len = hdr.encode(&mut triggering).unwrap();
    for b in &mut triggering[hdr_len..28] {
        *b = 0xaa;
    }

    let mut reset_pkt = [0u8; 32];
    let reset_len = key
        .encode_for_unknown_packet(&triggering[..28], &mut reset_pkt)
        .unwrap()
        .expect("valid short packet >= 21 bytes produces stateless reset");
    assert_eq!(reset_len, 28);
    assert!(reset_len >= STATELESS_RESET_MIN_PACKET_LEN);
    assert_eq!(reset_pkt[0] & 0xc0, 0);
    assert!(token.matches_packet(&reset_pkt[..reset_len]));
    assert!(!other_token.matches_packet(&reset_pkt[..reset_len]));
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn tokio_udp_link_sends_and_receives_stream_and_datagrams_into_pool() {
    use crate::udp::{TokioUdpLink, UdpSocketConfig, parse_udp_peer};
    use quic_base::DEFAULT_HEADROOM;

    assert_eq!(
        parse_udp_peer("udp://127.0.0.1", 4433).unwrap(),
        "127.0.0.1:4433".parse().unwrap()
    );

    let cfg = UdpSocketConfig {
        dscp: Some(10),
        receive_buffer_bytes: Some(64 * 1024),
        send_buffer_bytes: Some(64 * 1024),
    };
    let link_a = TokioUdpLink::bind_with_config("127.0.0.1:0".parse().unwrap(), cfg)
        .await
        .unwrap();
    let link_b = TokioUdpLink::bind_with_config("127.0.0.1:0".parse().unwrap(), cfg)
        .await
        .unwrap();
    let addr_a = link_a.local_addr().unwrap();
    let addr_b = link_b.local_addr().unwrap();

    let pool = XipLazyPool::with_default_geometry(32);
    let cid_ab = ConnectionId::new(10).unwrap();
    let cid_ba = ConnectionId::new(20).unwrap();

    let mut ep_a = SingleStreamEndpoint::new(
        pool.clone(),
        SingleStreamConfig {
            assoc: AssocConfig {
                local_cid: Some(cid_ba),
                ..AssocConfig::default()
            },
            ..SingleStreamConfig::default()
        },
    );
    let mut ep_b = SingleStreamEndpoint::new(
        pool.clone(),
        SingleStreamConfig {
            assoc: AssocConfig {
                local_cid: Some(cid_ab),
                ..AssocConfig::default()
            },
            ..SingleStreamConfig::default()
        },
    );
    let udp_id = LinkId(1);
    ep_a.assoc_mut()
        .upsert_link(udp_id, LinkProfile::udp_datagram(0, 1200, cid_ab));
    ep_b.assoc_mut()
        .upsert_link(udp_id, LinkProfile::udp_datagram(0, 1200, cid_ba));

    // Send both a reliable stream message and an unreliable DATAGRAM over real host UDP sockets!
    ep_a.write_stream(TxStreamData::Bytes(b"hello over real tokio udp"), true, 1_000)
        .unwrap();
    let mut dgram = pool.alloc().unwrap();
    dgram.append(b"unreliable udp datagram").unwrap();
    ep_a.send_datagram(dgram, StreamPriority::HIGH, 1_000).unwrap();

    while let Some(out) = ep_a.assoc_mut().pop_outbound_packet() {
        let outcome = link_a.send_packet(&out.packet, addr_b).await.unwrap();
        ep_a.assoc_mut()
            .on_driver_complete(out.link_id, out.packet_number, outcome, 1_000);
    }

    struct RecvCollector {
        stream: Vec<u8>,
        fin: bool,
        datagrams: Vec<Vec<u8>>,
    }
    impl SingleStreamCallbacks<XipLazyPacket> for RecvCollector {
        fn on_stream_data(
            &mut self,
            chunk: RxStreamChunk<'_, XipLazyPacket>,
            fin: bool,
        ) -> RxOutcome<XipLazyPacket> {
            let n = chunk.len();
            self.stream.extend_from_slice(chunk.as_slice());
            if fin {
                self.fin = true;
            }
            RxOutcome::Consumed(n)
        }
        fn on_datagram(&mut self, payload: XipLazyPacket) {
            self.datagrams.push(payload.bytes().to_vec());
        }
    }

    let mut cb_b = RecvCollector {
        stream: Vec::new(),
        fin: false,
        datagrams: Vec::new(),
    };
    for _ in 0..2 {
        let (pkt, peer) = link_b.recv_into_pool(&pool, DEFAULT_HEADROOM).await.unwrap();
        assert_eq!(peer, addr_a);
        ep_b.receive_packet(udp_id, pkt, 2_000, &mut cb_b).unwrap();
    }
    assert_eq!(cb_b.stream, b"hello over real tokio udp");
    assert!(cb_b.fin);
    assert_eq!(cb_b.datagrams, vec![b"unreliable udp datagram".to_vec()]);

    // Send B's ACK back over UDP to A and verify A's SACK ledger drains to 0!
    ep_b.poll_timers(2_000);
    while let Some(out) = ep_b.assoc_mut().pop_outbound_packet() {
        let outcome = link_b.send_packet(&out.packet, addr_a).await.unwrap();
        ep_b.assoc_mut()
            .on_driver_complete(out.link_id, out.packet_number, outcome, 2_000);
        let (pkt, peer) = link_a.recv_into_pool(&pool, DEFAULT_HEADROOM).await.unwrap();
        assert_eq!(peer, addr_b);
        let mut cb_a = RecvCollector {
            stream: Vec::new(),
            fin: false,
            datagrams: Vec::new(),
        };
        ep_a.receive_packet(udp_id, pkt, 3_000, &mut cb_a).unwrap();
    }
    assert_eq!(ep_a.assoc().sack_ledger().retained_packets(), 0);
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn tokio_mux_streams_over_udp_assoc_packet_link() {
    use crate::udp::{TokioUdpLink, spawn_udp_packet_link};
    use quic_mux::tokio_mux::{TokioMux, TokioMuxConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let udp_a = TokioUdpLink::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let udp_b = TokioUdpLink::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr_a = udp_a.local_addr().unwrap();
    let addr_b = udp_b.local_addr().unwrap();

    let cid = ConnectionId::new(42).unwrap();
    let (tx_a, rx_a, _task_a) = spawn_udp_packet_link(udp_a, addr_b, cid);
    let (tx_b, rx_b, _task_b) = spawn_udp_packet_link(udp_b, addr_a, cid);

    let (client_mux, _client_acceptor) = TokioMux::spawn(true, TokioMuxConfig::default());
    let (server_mux, mut server_acceptor) = TokioMux::spawn(false, TokioMuxConfig::default());

    client_mux.add_packet_link(tx_a, rx_a, 1180, 10);
    server_mux.add_packet_link(tx_b, rx_b, 1180, 10);

    let server_task = tokio::spawn(async move {
        let mut handled = Vec::new();
        for _ in 0..3 {
            let mut stream = server_acceptor.accept().await.expect("accept stream");
            handled.push(tokio::spawn(async move {
                let mut req = Vec::new();
                stream.read_to_end(&mut req).await.unwrap();
                let mut reply = b"ack:".to_vec();
                reply.extend_from_slice(&req);
                stream.write_all(&reply).await.unwrap();
                stream.shutdown().await.unwrap();
            }));
        }
        for h in handled {
            h.await.unwrap();
        }
    });

    let mut client_tasks = Vec::new();
    for idx in 0..3u8 {
        let mux = client_mux.clone();
        client_tasks.push(tokio::spawn(async move {
            let mut stream = mux.open_bidi().await.unwrap();
            let payload = vec![b'0' + idx; 2048];
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.unwrap();
            assert_eq!(&resp[..4], b"ack:");
            assert_eq!(&resp[4..], payload.as_slice());
        }));
    }

    for ct in client_tasks {
        ct.await.unwrap();
    }
    server_task.await.unwrap();
    let _ = server_mux;
}
