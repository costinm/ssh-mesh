use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use crate::{
    AckRange, AssociationBrokenReason, AssociationEgress, AssociationId, AssociationLimits,
    DEFAULT_HEADROOM, LinkSendError, MuxCallbacks, MuxLimits, MuxSendError, PacketPool, PoolPacket,
    QuicMux, RxMeta, RxOutcome, RxStreamChunk, SackRetransmitLedger, SlabPacket, SlabPool,
    StreamCloseReason, StreamError, StreamId, StreamPriority, TxPacketMeta, TxStreamData,
};

struct CostOrderedLinks {
    link0_ready: bool,
    link1_ready: bool,
    mtu: usize,
    link0_sent: VecDeque<(TxPacketMeta, SlabPacket)>,
    link1_sent: VecDeque<(TxPacketMeta, SlabPacket)>,
    aborted_streams: Vec<(AssociationId, StreamId)>,
}

impl CostOrderedLinks {
    fn new(mtu: usize) -> Self {
        Self {
            link0_ready: true,
            link1_ready: true,
            mtu,
            link0_sent: VecDeque::new(),
            link1_sent: VecDeque::new(),
            aborted_streams: Vec::new(),
        }
    }
}

impl AssociationEgress<SlabPacket> for CostOrderedLinks {
    fn send_packet(
        &mut self,
        meta: TxPacketMeta,
        packet: SlabPacket,
    ) -> Result<(), LinkSendError<SlabPacket>> {
        if packet.bytes().len() > self.mtu {
            return Err(LinkSendError::TooLarge {
                packet,
                max_frame_len: self.mtu,
            });
        }
        // Association layer selects the actual link in cost order: link 0 first, then link 1
        if self.link0_ready {
            self.link0_sent.push_back((meta, packet));
            Ok(())
        } else if self.link1_ready {
            self.link1_sent.push_back((meta, packet));
            Ok(())
        } else {
            Err(LinkSendError::Busy(packet))
        }
    }

    fn max_writable_frame_len(&self, _assoc: AssociationId) -> usize {
        if self.link0_ready || self.link1_ready {
            self.mtu
        } else {
            0
        }
    }

    fn on_stream_aborted(&mut self, assoc: AssociationId, stream_id: StreamId) {
        self.aborted_streams.push((assoc, stream_id));
    }
}

#[derive(Default)]
struct RecordingCallbacks {
    received: Vec<(AssociationId, StreamId, u64, Vec<u8>, bool)>,
    forwarded_packets: Vec<SlabPacket>,
    retain_credit: bool,
    partial_consume_limit: Option<usize>,
    closed_streams: Vec<(AssociationId, StreamId, StreamCloseReason)>,
    broken_associations: Vec<(AssociationId, AssociationBrokenReason)>,
    writable_streams: Vec<(AssociationId, StreamId, usize)>,
    writable_associations: Vec<(AssociationId, u64)>,
    device_writable_count: usize,
}

impl MuxCallbacks<SlabPacket> for RecordingCallbacks {
    fn on_stream_data(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        offset: u64,
        mut chunk: RxStreamChunk<'_, SlabPacket>,
        fin: bool,
    ) -> Result<RxOutcome<SlabPacket>, StreamError> {
        if let Some(limit) = self.partial_consume_limit {
            if chunk.len() > limit {
                self.received.push((
                    assoc,
                    stream_id,
                    offset,
                    chunk.as_slice()[..limit].to_vec(),
                    false,
                ));
                let pkt = chunk.take_packet().expect("owned pool packet");
                return Ok(RxOutcome::Partial {
                    consumed: limit,
                    packet: pkt,
                });
            }
        }

        self.received
            .push((assoc, stream_id, offset, chunk.as_slice().to_vec(), fin));
        let len = chunk.len();
        if let Some(pkt) = chunk.take_packet() {
            self.forwarded_packets.push(pkt);
        }
        if self.retain_credit {
            Ok(RxOutcome::RetainedPendingCredit)
        } else {
            Ok(RxOutcome::Consumed(len))
        }
    }

    fn on_stream_closed(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        reason: StreamCloseReason,
    ) {
        self.closed_streams.push((assoc, stream_id, reason));
    }

    fn on_association_broken(&mut self, assoc: AssociationId, reason: AssociationBrokenReason) {
        self.broken_associations.push((assoc, reason));
    }

    fn on_stream_writable(
        &mut self,
        assoc: AssociationId,
        stream_id: StreamId,
        writable_bytes: usize,
    ) {
        self.writable_streams
            .push((assoc, stream_id, writable_bytes));
    }

    fn on_association_writable(&mut self, assoc: AssociationId, association_window: u64) {
        self.writable_associations.push((assoc, association_window));
    }

    fn on_device_writable(&mut self) {
        self.device_writable_count += 1;
    }
}

#[test]
fn zero_copy_prefix_headroom_and_busy_rollback() {
    let pool = SlabPool::with_default_geometry(4);
    let mut mux = QuicMux::new(pool.clone(), MuxLimits::default());
    let assoc = AssociationId(1);
    mux.add_association(assoc, true).unwrap();
    let stream = mux
        .open_stream_with_priority(assoc, true, StreamPriority::HIGH)
        .unwrap();

    // Allocate a packet from the pool; payload starts at DEFAULT_HEADROOM (144)
    let mut pkt = pool.alloc().unwrap();
    assert_eq!(pkt.range(), DEFAULT_HEADROOM..DEFAULT_HEADROOM);
    pkt.append(b"hello-zero-copy").unwrap();
    let orig_range = pkt.range();
    let orig_slot_ptr = pkt.slot_ptr();
    let orig_payload_ptr = pkt.payload_ptr();
    assert_eq!(orig_range, 144..(144 + 15));

    struct RefusingLink;
    impl AssociationEgress<SlabPacket> for RefusingLink {
        fn send_packet(
            &mut self,
            _meta: TxPacketMeta,
            packet: SlabPacket,
        ) -> Result<(), LinkSendError<SlabPacket>> {
            Err(LinkSendError::Busy(packet))
        }
        fn max_writable_frame_len(&self, _assoc: AssociationId) -> usize {
            1200
        }
    }

    let err = mux
        .write_stream(
            assoc,
            stream,
            TxStreamData::Packet(pkt),
            false,
            &mut RefusingLink,
        )
        .unwrap_err();
    let MuxSendError::Busy(Some(returned_pkt)) = err else {
        panic!("expected Busy with returned packet");
    };
    assert_eq!(returned_pkt.range(), orig_range);
    assert_eq!(returned_pkt.bytes(), b"hello-zero-copy");
    assert_eq!(returned_pkt.slot_ptr(), orig_slot_ptr);
    assert_eq!(returned_pkt.payload_ptr(), orig_payload_ptr);

    // Now send when link0 is ready: header is prepended in-place before offset 144
    let mut links = CostOrderedLinks::new(1200);
    let sent = mux
        .write_stream(
            assoc,
            stream,
            TxStreamData::Packet(returned_pkt),
            true,
            &mut links,
        )
        .unwrap();
    assert_eq!(sent, 15);
    assert_eq!(links.link0_sent.len(), 1);
    let (meta, wire_pkt) = links.link0_sent.pop_front().unwrap();
    assert_eq!(meta.association, assoc);
    assert_eq!(meta.stream_id, Some(stream));
    assert_eq!(meta.priority, StreamPriority::HIGH);
    assert!(meta.retransmittable);
    assert_eq!(wire_pkt.slot_ptr(), orig_slot_ptr);
    assert!(wire_pkt.range().start < DEFAULT_HEADROOM);
    assert_eq!(wire_pkt.range().end, DEFAULT_HEADROOM + 15);
    assert_eq!(&wire_pkt.slot_slice()[orig_range], b"hello-zero-copy");
}

#[test]
fn zero_copy_proxy_gateway_forwarding_end_to_end() {
    let pool = SlabPool::with_default_geometry(4);
    assert_eq!(pool.available(), 4);

    let mut sender_mux = QuicMux::new(pool.clone(), MuxLimits::default());
    let mut proxy_mux = QuicMux::new(pool.clone(), MuxLimits::default());
    let mut receiver_mux = QuicMux::new(pool.clone(), MuxLimits::default());

    let assoc_in = AssociationId(10);
    let assoc_out = AssociationId(20);

    sender_mux.add_association(assoc_in, true).unwrap();
    proxy_mux.add_association(assoc_in, false).unwrap();
    proxy_mux.add_association(assoc_out, true).unwrap();
    receiver_mux.add_association(assoc_out, false).unwrap();

    let s_in = sender_mux.open_stream(assoc_in, true).unwrap();
    let s_out = proxy_mux.open_stream(assoc_out, true).unwrap();

    // Allocate 1 packet at sender, write payload at headroom 144..144+20
    let mut pkt = pool.alloc().unwrap();
    pkt.append(b"gateway-zero-copy-ok").unwrap();
    let original_slot_ptr = pkt.slot_ptr();
    let original_payload_ptr = pkt.payload_ptr();
    assert_eq!(pool.available(), 3);

    let mut hop1_links = CostOrderedLinks::new(1200);
    sender_mux
        .write_stream(assoc_in, s_in, TxStreamData::Packet(pkt), true, &mut hop1_links)
        .unwrap();
    let (_, hop1_wire_pkt) = hop1_links.link0_sent.pop_front().unwrap();
    assert_eq!(hop1_wire_pkt.slot_ptr(), original_slot_ptr);

    // Proxy receives hop1_wire_pkt; callback takes ownership of `SlabPacket` (`is_unique() == true`)
    let mut proxy_cb = RecordingCallbacks::default();
    proxy_mux
        .receive_packet(
            RxMeta {
                association: assoc_in,
                received_at_us: 1_000,
            },
            hop1_wire_pkt,
            &mut hop1_links,
            &mut proxy_cb,
        )
        .unwrap();

    assert_eq!(proxy_cb.forwarded_packets.len(), 1);
    let rx_owned_pkt = proxy_cb.forwarded_packets.pop().unwrap();
    assert!(rx_owned_pkt.is_unique());
    assert_eq!(rx_owned_pkt.slot_ptr(), original_slot_ptr);
    assert_eq!(rx_owned_pkt.payload_ptr(), original_payload_ptr);
    assert_eq!(rx_owned_pkt.bytes(), b"gateway-zero-copy-ok");
    assert_eq!(pool.available(), 3);

    // Proxy immediately forwards `rx_owned_pkt` onto `assoc_out` / `s_out` with zero copies
    let mut hop2_links = CostOrderedLinks::new(1200);
    proxy_mux
        .write_stream(
            assoc_out,
            s_out,
            TxStreamData::Packet(rx_owned_pkt),
            true,
            &mut hop2_links,
        )
        .unwrap();

    let (_, hop2_wire_pkt) = hop2_links.link0_sent.pop_front().unwrap();
    assert_eq!(hop2_wire_pkt.slot_ptr(), original_slot_ptr);
    assert_eq!(pool.available(), 3);

    // Final destination receives hop2_wire_pkt
    let mut dst_cb = RecordingCallbacks::default();
    receiver_mux
        .receive_packet(
            RxMeta {
                association: assoc_out,
                received_at_us: 2_000,
            },
            hop2_wire_pkt,
            &mut hop2_links,
            &mut dst_cb,
        )
        .unwrap();

    assert_eq!(dst_cb.received.len(), 1);
    assert_eq!(dst_cb.received[0].3, b"gateway-zero-copy-ok");
    assert!(dst_cb.received[0].4);
    let dst_pkt = dst_cb.forwarded_packets.pop().unwrap();
    assert_eq!(dst_pkt.slot_ptr(), original_slot_ptr);
    assert_eq!(dst_pkt.payload_ptr(), original_payload_ptr);
    drop(dst_pkt);
    assert_eq!(pool.available(), 4);
}

#[test]
fn multi_link_failover_and_out_of_order_reassembly() {
    let pool = SlabPool::with_default_geometry(8);
    let mut tx_mux = QuicMux::new(pool.clone(), MuxLimits::default());
    let mut rx_mux = QuicMux::new(pool.clone(), MuxLimits::default());

    let assoc = AssociationId(1);
    tx_mux.add_association(assoc, true).unwrap();
    rx_mux.add_association(assoc, false).unwrap();
    let stream = tx_mux.open_stream(assoc, true).unwrap();

    let mut links = CostOrderedLinks::new(1200);
    tx_mux
        .write_stream(assoc, stream, TxStreamData::Bytes(b"part-1:"), false, &mut links)
        .unwrap();
    assert_eq!(links.link0_sent.len(), 1);

    // Link 0 becomes busy; Packet 2 automatically fails over to link 1
    links.link0_ready = false;
    tx_mux
        .write_stream(assoc, stream, TxStreamData::Bytes(b"part-2!"), true, &mut links)
        .unwrap();
    assert_eq!(links.link1_sent.len(), 1);

    let (_, pkt1) = links.link0_sent.pop_front().unwrap();
    let (_, pkt2) = links.link1_sent.pop_front().unwrap();

    let mut cb = RecordingCallbacks::default();
    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 10_000,
            },
            pkt2,
            &mut links,
            &mut cb,
        )
        .unwrap();
    assert!(cb.received.is_empty());
    assert_eq!(rx_mux.next_deadline(), Some(3_010_000));

    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 15_000,
            },
            pkt1,
            &mut links,
            &mut cb,
        )
        .unwrap();

    assert_eq!(cb.received.len(), 2);
    assert_eq!(cb.received[0].2, 0);
    assert_eq!(cb.received[0].3, b"part-1:");
    assert!(!cb.received[0].4);
    assert_eq!(cb.received[1].2, 7);
    assert_eq!(cb.received[1].3, b"part-2!");
    assert!(cb.received[1].4);
    assert_eq!(rx_mux.next_deadline(), None);
}

#[test]
fn missing_middle_frame_timeout_marks_stream_and_association_broken() {
    let pool = SlabPool::with_default_geometry(8);
    let limits = MuxLimits {
        gap_timeout_us: 500_000,
        ..MuxLimits::default()
    };
    let mut tx_mux = QuicMux::new(pool.clone(), limits);
    let mut rx_mux = QuicMux::new(pool.clone(), limits);

    let assoc = AssociationId(7);
    tx_mux.add_association(assoc, true).unwrap();
    rx_mux.add_association(assoc, false).unwrap();
    let stream = tx_mux.open_stream(assoc, true).unwrap();

    let mut links = CostOrderedLinks::new(1200);
    tx_mux
        .write_stream(assoc, stream, TxStreamData::Bytes(b"first-"), false, &mut links)
        .unwrap();
    tx_mux
        .write_stream(assoc, stream, TxStreamData::Bytes(b"middle-"), false, &mut links)
        .unwrap();
    tx_mux
        .write_stream(assoc, stream, TxStreamData::Bytes(b"last"), true, &mut links)
        .unwrap();

    let (_, pkt1) = links.link0_sent.pop_front().unwrap();
    let (_, _pkt2_dropped_in_middlebox) = links.link0_sent.pop_front().unwrap();
    let (_, pkt3) = links.link0_sent.pop_front().unwrap();
    drop(_pkt2_dropped_in_middlebox);

    let mut cb = RecordingCallbacks::default();
    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 1_000,
            },
            pkt1,
            &mut links,
            &mut cb,
        )
        .unwrap();
    cb.forwarded_packets.clear();
    assert_eq!(cb.received.len(), 1);

    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 20_000,
            },
            pkt3,
            &mut links,
            &mut cb,
        )
        .unwrap();
    assert_eq!(pool.available(), 7);
    assert_eq!(rx_mux.next_deadline(), Some(520_000));

    links.link0_sent.clear();
    links.aborted_streams.clear();
    assert_eq!(rx_mux.advance_time(519_999, &mut links, &mut cb), 0);
    assert!(links.link0_sent.is_empty());
    assert_eq!(rx_mux.advance_time(520_000, &mut links, &mut cb), 1);
    assert_eq!(links.aborted_streams, vec![(assoc, stream)]);
    assert!(!links.link0_sent.is_empty());
    let (_, abort_pkt) = links.link0_sent.pop_front().unwrap();
    let (f0, next0) = crate::wire::decode_frame(abort_pkt.bytes(), 0).unwrap();
    let (f1, next1) = crate::wire::decode_frame(abort_pkt.bytes(), next0).unwrap();
    assert_eq!(next1, abort_pkt.bytes().len());
    assert_eq!(
        f0,
        crate::Frame::ResetStream {
            stream_id: stream,
            error_code: crate::GAP_TIMEOUT_ERROR_CODE,
            final_size: 0,
        }
    );
    assert_eq!(
        f1,
        crate::Frame::StopSending {
            stream_id: stream,
            error_code: crate::GAP_TIMEOUT_ERROR_CODE,
        }
    );
    drop(abort_pkt);
    links.link0_sent.clear();
    assert_eq!(
        cb.closed_streams,
        vec![(
            assoc,
            stream,
            StreamCloseReason::GapTimeout { missing_offset: 6 }
        )]
    );
    assert_eq!(
        cb.broken_associations,
        vec![(
            assoc,
            AssociationBrokenReason::StreamGapTimeout {
                stream_id: stream,
                missing_offset: 6,
            }
        )]
    );
    assert_eq!(pool.available(), 8);
}

#[test]
fn three_tier_flow_control_and_deferred_credit() {
    let pool = SlabPool::with_default_geometry(8);
    let limits = MuxLimits {
        initial_max_data: 32,
        initial_max_stream_data: 16,
        ..MuxLimits::default()
    };
    let mut client = QuicMux::new(pool.clone(), limits);
    let mut server = QuicMux::new(pool.clone(), limits);

    let assoc = AssociationId(1);
    client.add_association(assoc, true).unwrap();
    server.add_association(assoc, false).unwrap();
    let stream = client.open_stream(assoc, true).unwrap();

    let mut links = CostOrderedLinks::new(1200);
    let mut client_cb = RecordingCallbacks::default();
    let mut server_cb = RecordingCallbacks {
        retain_credit: true,
        ..RecordingCallbacks::default()
    };

    client.set_device_capacity(0, &mut client_cb);
    let cap = client.stream_send_capacity(assoc, stream, &links).unwrap();
    assert_eq!(cap.max_chunk_bytes, 0);
    assert!(!cap.can_send_now);

    assert!(matches!(
        client.write_stream(assoc, stream, TxStreamData::Bytes(b"blocked"), false, &mut links),
        Err(MuxSendError::FlowControl(None))
    ));

    client.set_device_capacity(1024, &mut client_cb);
    assert_eq!(client_cb.device_writable_count, 1);

    client
        .write_stream(
            assoc,
            stream,
            TxStreamData::Bytes(b"0123456789abcdef"),
            false,
            &mut links,
        )
        .unwrap();
    assert_eq!(
        client
            .stream_send_capacity(assoc, stream, &links)
            .unwrap()
            .stream_window,
        0
    );

    let (_, pkt) = links.link0_sent.pop_front().unwrap();
    server
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 1_000,
            },
            pkt,
            &mut links,
            &mut server_cb,
        )
        .unwrap();
    assert!(links.link0_sent.is_empty());

    server_cb.forwarded_packets.clear();
    server
        .release_stream_credit(assoc, stream, 16, &mut links)
        .unwrap();
    assert_eq!(links.link0_sent.len(), 1);

    let (_, ctrl_pkt) = links.link0_sent.pop_front().unwrap();
    client
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 2_000,
            },
            ctrl_pkt,
            &mut links,
            &mut client_cb,
        )
        .unwrap();
    assert_eq!(client_cb.writable_streams, vec![(assoc, stream, 16)]);
}

#[test]
fn partial_consumption_and_resume_stream() {
    let pool = SlabPool::with_default_geometry(4);
    let mut tx_mux = QuicMux::new(pool.clone(), MuxLimits::default());
    let mut rx_mux = QuicMux::new(pool.clone(), MuxLimits::default());

    let assoc = AssociationId(3);
    tx_mux.add_association(assoc, true).unwrap();
    rx_mux.add_association(assoc, false).unwrap();
    let stream = tx_mux.open_stream(assoc, true).unwrap();

    let mut links = CostOrderedLinks::new(1200);
    tx_mux
        .write_stream(
            assoc,
            stream,
            TxStreamData::Bytes(b"0123456789"),
            true,
            &mut links,
        )
        .unwrap();
    let (_, pkt) = links.link0_sent.pop_front().unwrap();

    let mut cb = RecordingCallbacks {
        partial_consume_limit: Some(4),
        ..RecordingCallbacks::default()
    };
    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 100,
            },
            pkt,
            &mut links,
            &mut cb,
        )
        .unwrap();
    assert_eq!(cb.received.len(), 1);
    assert_eq!(cb.received[0].3, b"0123");
    assert!(!cb.received[0].4);
    assert_eq!(pool.available(), 3);

    cb.partial_consume_limit = None;
    let delivered = rx_mux
        .resume_stream(assoc, stream, 200, &mut links, &mut cb)
        .unwrap();
    assert_eq!(delivered, 6);
    assert_eq!(cb.received.len(), 2);
    assert_eq!(cb.received[1].2, 4);
    assert_eq!(cb.received[1].3, b"456789");
    assert!(cb.received[1].4);
    cb.forwarded_packets.clear();
    assert_eq!(pool.available(), 4);
}

#[test]
fn rx_out_of_order_pressure_evicts_lowest_priority_stream_and_dynamic_limits() {
    let pool = SlabPool::with_default_geometry(16);
    let limits = MuxLimits {
        max_association_rx_packets: 2,
        max_device_rx_packets: 4,
        max_queued_chunks_per_stream: 4,
        ..MuxLimits::default()
    };
    let mut tx_mux = QuicMux::new(pool.clone(), limits);
    let mut rx_mux = QuicMux::new(pool.clone(), limits);

    let assoc = AssociationId(1);
    tx_mux.add_association(assoc, true).unwrap();
    rx_mux.add_association(assoc, false).unwrap();

    // Open a BULK stream (priority 255) and a HIGH stream (priority 64)
    let bulk_stream = tx_mux
        .open_stream_with_priority(assoc, true, StreamPriority::BULK)
        .unwrap();
    let high_stream = tx_mux
        .open_stream_with_priority(assoc, true, StreamPriority::HIGH)
        .unwrap();

    let mut links = CostOrderedLinks::new(1200);
    let mut cb = RecordingCallbacks::default();

    // Send 1st (in-order) packet on both streams so rx_mux creates both streams, then configure priorities on rx_mux
    tx_mux
        .write_stream(assoc, bulk_stream, TxStreamData::Bytes(b"b0"), false, &mut links)
        .unwrap();
    tx_mux
        .write_stream(assoc, high_stream, TxStreamData::Bytes(b"h0"), false, &mut links)
        .unwrap();
    let (_, b0) = links.link0_sent.pop_front().unwrap();
    let (_, h0) = links.link0_sent.pop_front().unwrap();
    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 10,
            },
            b0,
            &mut links,
            &mut cb,
        )
        .unwrap();
    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 20,
            },
            h0,
            &mut links,
            &mut cb,
        )
        .unwrap();
    cb.forwarded_packets.clear();
    rx_mux
        .set_stream_priority(assoc, bulk_stream, StreamPriority::BULK)
        .unwrap();
    rx_mux
        .set_stream_priority(assoc, high_stream, StreamPriority::HIGH)
        .unwrap();

    // Create gaps on both streams and send 2 out-of-order packets on `bulk_stream` (fills `max_association_rx_packets = 2`)
    tx_mux
        .write_stream(assoc, bulk_stream, TxStreamData::Bytes(b"b1_gap"), false, &mut links)
        .unwrap();
    tx_mux
        .write_stream(assoc, bulk_stream, TxStreamData::Bytes(b"b2_ooo"), false, &mut links)
        .unwrap();
    tx_mux
        .write_stream(assoc, bulk_stream, TxStreamData::Bytes(b"b3_ooo"), false, &mut links)
        .unwrap();
    let _b1_gap = links.link0_sent.pop_front().unwrap();
    let (_, b2_ooo) = links.link0_sent.pop_front().unwrap();
    let (_, b3_ooo) = links.link0_sent.pop_front().unwrap();

    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 100,
            },
            b2_ooo,
            &mut links,
            &mut cb,
        )
        .unwrap();
    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 110,
            },
            b3_ooo,
            &mut links,
            &mut cb,
        )
        .unwrap();
    assert_eq!(rx_mux.association_rx_queued_packets(assoc), Some(2));
    assert!(cb.closed_streams.is_empty());

    // Now `high_stream` receives an out-of-order packet while `assoc` is at its RX packet limit (2).
    // `rx_mux` evicts/RSTs `bulk_stream` (`StreamCloseReason::ResourcePressure`), frees its 2 packets,
    // notifies `links.on_stream_aborted`, and admits `high_stream`'s out-of-order packet!
    tx_mux
        .write_stream(assoc, high_stream, TxStreamData::Bytes(b"h1_gap"), false, &mut links)
        .unwrap();
    tx_mux
        .write_stream(assoc, high_stream, TxStreamData::Bytes(b"h2_ooo"), false, &mut links)
        .unwrap();
    tx_mux
        .write_stream(assoc, high_stream, TxStreamData::Bytes(b"h3_ooo"), false, &mut links)
        .unwrap();
    let _h1_gap = links.link0_sent.pop_front().unwrap();
    let (_, h2_ooo) = links.link0_sent.pop_front().unwrap();
    let (_, h3_ooo) = links.link0_sent.pop_front().unwrap();

    // Drain any RESET_STREAM control packet emitted when `bulk_stream` is aborted
    links.link0_sent.clear();
    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 200,
            },
            h2_ooo,
            &mut links,
            &mut cb,
        )
        .unwrap();
    assert_eq!(
        cb.closed_streams,
        vec![(
            assoc,
            bulk_stream,
            StreamCloseReason::ResourcePressure {
                delivered_offset: 2
            }
        )]
    );
    assert_eq!(links.aborted_streams, vec![(assoc, bulk_stream)]);
    assert_eq!(rx_mux.association_rx_queued_packets(assoc), Some(1));

    // Queue a 2nd out-of-order packet on `high_stream`
    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 210,
            },
            h3_ooo,
            &mut links,
            &mut cb,
        )
        .unwrap();
    assert_eq!(rx_mux.total_rx_queued_packets(), 2);

    // Now simulate system load spike: dynamically lower `device_rx_packet_limit` to 1!
    // `set_device_rx_packet_limit` immediately evicts `high_stream` to bring retained RX packets <= 1.
    let evicted = rx_mux.set_device_rx_packet_limit(1, &mut links, &mut cb);
    assert_eq!(evicted, 1);
    assert_eq!(rx_mux.total_rx_queued_packets(), 0);
    assert_eq!(cb.closed_streams.len(), 2);
    assert_eq!(
        cb.closed_streams[1],
        (
            assoc,
            high_stream,
            StreamCloseReason::ResourcePressure {
                delivered_offset: 2
            }
        )
    );

    // Also verify dynamic `set_association_limits` can increase limits when load subsides
    let evicted2 = rx_mux
        .set_association_limits(
            assoc,
            AssociationLimits {
                max_concurrent_streams: 32,
                max_rx_queued_packets: 8,
                max_rx_queued_packets_per_stream: 4,
            },
            &mut links,
            &mut cb,
        )
        .unwrap();
    assert_eq!(evicted2, 0);
}

#[test]
fn association_sack_retransmit_and_tx_pressure_eviction() {
    let pool = SlabPool::with_default_geometry(12);
    let mut tx_mux = QuicMux::new(pool.clone(), MuxLimits::default());
    let mut rx_mux = QuicMux::new(pool.clone(), MuxLimits::default());

    let assoc = AssociationId(5);
    tx_mux.add_association(assoc, true).unwrap();
    rx_mux.add_association(assoc, false).unwrap();

    let high_stream = tx_mux
        .open_stream_with_priority(assoc, true, StreamPriority::HIGH)
        .unwrap();
    let bulk_stream = tx_mux
        .open_stream_with_priority(assoc, true, StreamPriority::BULK)
        .unwrap();

    // Association layer SACK & Retransmit ledger with dynamic limit = 3 packets
    let mut sack_ledger = SackRetransmitLedger::<SlabPacket>::new(3);
    let mut links = CostOrderedLinks::new(1200);
    let mut cb = RecordingCallbacks::default();

    // Send 2 packets on `high_stream` (pkt_num 1, 2) and 1 packet on `bulk_stream` (pkt_num 3)
    tx_mux
        .write_stream(assoc, high_stream, TxStreamData::Bytes(b"h-pkt-1:"), false, &mut links)
        .unwrap();
    tx_mux
        .write_stream(assoc, high_stream, TxStreamData::Bytes(b"h-pkt-2!"), true, &mut links)
        .unwrap();
    tx_mux
        .write_stream(assoc, bulk_stream, TxStreamData::Bytes(b"b-pkt-3"), false, &mut links)
        .unwrap();

    // Association layer records all 3 packets in `sack_ledger` before sending on physical links
    for (idx, (meta, pkt)) in links.link0_sent.drain(..).enumerate() {
        let (pnum, evicted) = sack_ledger
            .record_tx(meta, pkt, (idx as u64 + 1) * 100)
            .unwrap();
        assert_eq!(pnum, idx as u64 + 1);
        assert!(evicted.is_empty());
    }
    assert_eq!(sack_ledger.retained_packets(), 3);

    // Peer sends a Selective ACK (SACK) acknowledging packet 2 (`AckRange::new(2, 2)`), while packet 1 was lost!
    let retransmits = sack_ledger.on_selective_ack(assoc, &[AckRange::new(2, 2)], 1);
    assert_eq!(retransmits.len(), 1);
    assert_eq!(retransmits[0].original_pkt_num, 1);
    assert_eq!(retransmits[0].meta.stream_id, Some(high_stream));
    // Packet 2 was freed by SACK; packets 1 and 3 remain in the ledger
    assert_eq!(sack_ledger.retained_packets(), 2);

    // Now system load increases and the association layer lowers `max_retained_packets` from 3 to 1:
    // `sack_ledger` evicts the lowest-priority stream (`bulk_stream`, pkt 3) and returns `(assoc, bulk_stream)`
    // so `tx_mux` can RST `bulk_stream`!
    let evicted = sack_ledger.set_max_retained_packets(1);
    assert_eq!(evicted, vec![(assoc, bulk_stream)]);
    assert_eq!(sack_ledger.retained_packets(), 1);
    for (ev_assoc, ev_stream) in evicted {
        assert!(tx_mux.abort_stream_under_pressure(ev_assoc, ev_stream, &mut links, &mut cb));
    }
    assert_eq!(
        cb.closed_streams,
        vec![(
            assoc,
            bulk_stream,
            StreamCloseReason::ResourcePressure {
                delivered_offset: 0
            }
        )]
    );

    // Deliver the SACK-retransmitted packet 1 to `rx_mux` -> `high_stream` receives "h-pkt-1:" intact!
    let mut rx_cb = RecordingCallbacks::default();
    let retx_pkt = retransmits.into_iter().next().unwrap().packet;
    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 500,
            },
            retx_pkt,
            &mut links,
            &mut rx_cb,
        )
        .unwrap();
    assert_eq!(rx_cb.received.len(), 1);
    assert_eq!(rx_cb.received[0].1, high_stream);
    assert_eq!(rx_cb.received[0].3, b"h-pkt-1:");
}

#[test]
fn pool_implementations_static_heap_and_xip_lazy_semantics() {
    use crate::{HeapPacketPool, StaticPacketPool, XipLazyPool};

    // 1. StaticPacketPool (quic-lite inline pool)
    static STATIC_POOL: StaticPacketPool<4> = StaticPacketPool::new();
    assert_eq!(STATIC_POOL.available(), 4);
    let mut s_pkt = (&STATIC_POOL).alloc_reserving(1).unwrap();
    s_pkt.append(b"static-pool").unwrap();
    s_pkt.prepend(b"hdr:").unwrap();
    assert_eq!(s_pkt.bytes(), b"hdr:static-pool");
    assert_eq!(STATIC_POOL.available(), 3);
    drop(s_pkt);
    assert_eq!(STATIC_POOL.available(), 4);

    // 2. HeapPacketPool (quic-lite dynamically resizable heap pool)
    static HEAP_POOL: HeapPacketPool<8> = HeapPacketPool::new();
    HEAP_POOL.resize(4).unwrap();
    assert_eq!(HEAP_POOL.available(), 4);
    let mut h_pkt = (&HEAP_POOL).alloc().unwrap();
    h_pkt.append(b"heap-pool").unwrap();
    let h_clone = h_pkt.try_clone().unwrap();
    assert!(!h_pkt.is_unique());
    drop(h_clone);
    assert!(h_pkt.is_unique());
    h_pkt.prepend(b"ok:").unwrap();
    assert_eq!(h_pkt.bytes(), b"ok:heap-pool");
    HEAP_POOL.resize(0).unwrap();
    // Slot is retired once `h_pkt` drops
    assert_eq!(HEAP_POOL.allocated(), 1);
    drop(h_pkt);
    assert_eq!(HEAP_POOL.allocated(), 0);

    // 3. XipLazyPool (replicates ESP-XIP C `xip_pool.c` & `xip-runtime-host::pool::Pool`)
    let xip_pool = XipLazyPool::with_default_geometry(8);
    assert_eq!(xip_pool.allocated(), 0);
    xip_pool.prepare_rx();
    assert_eq!(xip_pool.cached_available(), 2); // `keep = 2` warm idle slots prepared

    let all: Vec<_> = (0..8).map(|_| xip_pool.alloc().unwrap()).collect();
    assert_eq!(xip_pool.allocated(), 8);
    assert_eq!(xip_pool.available(), 0);
    let handle0 = xip_pool.packet_handle(&all[0]);
    assert!(xip_pool.get_handle(handle0).is_some());
    drop(all);
    // Releasing all 8 slots automatically frees 6 buffers and keeps `keep = 2` warm idle buffers!
    assert_eq!(xip_pool.allocated(), 2);
    assert_eq!(xip_pool.available(), 8);
    // Stale generation handle is rejected after release + re-acquire
    let next_pkt = xip_pool.acquire_cached(0).unwrap();
    assert!(xip_pool.get_handle(handle0).is_none());
    drop(next_pkt);
    xip_pool.set_keep(0);
    xip_pool.trim();
    assert_eq!(xip_pool.allocated(), 0);
}

// ============================================================================
// Global Counting Allocator & Memory/Allocation Instrumentation for Benchmarks
// ============================================================================

struct CountingAllocator;

static ALLOC_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static DEALLOC_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static REALLOC_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static BYTES_ALLOCATED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static CURRENT_LIVE_BYTES: core::sync::atomic::AtomicIsize = core::sync::atomic::AtomicIsize::new(0);
static PEAK_LIVE_BYTES: core::sync::atomic::AtomicIsize = core::sync::atomic::AtomicIsize::new(0);

#[global_allocator]
static GLOBAL_COUNTING_ALLOCATOR: CountingAllocator = CountingAllocator;

unsafe impl core::alloc::GlobalAlloc for CountingAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let ptr = unsafe { std::alloc::System.alloc(layout) };
        if !ptr.is_null() {
            let sz = layout.size();
            ALLOC_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            BYTES_ALLOCATED.fetch_add(sz as u64, core::sync::atomic::Ordering::Relaxed);
            let live = CURRENT_LIVE_BYTES
                .fetch_add(sz as isize, core::sync::atomic::Ordering::Relaxed)
                + sz as isize;
            PEAK_LIVE_BYTES.fetch_max(live, core::sync::atomic::Ordering::Relaxed);
        }
        ptr
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) };
        let sz = layout.size();
        DEALLOC_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        CURRENT_LIVE_BYTES.fetch_sub(sz as isize, core::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        layout: core::alloc::Layout,
        new_size: usize,
    ) -> *mut u8 {
        let new_ptr = unsafe { std::alloc::System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            let old_size = layout.size();
            REALLOC_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if new_size > old_size {
                let diff = new_size - old_size;
                BYTES_ALLOCATED.fetch_add(diff as u64, core::sync::atomic::Ordering::Relaxed);
                let live = CURRENT_LIVE_BYTES
                    .fetch_add(diff as isize, core::sync::atomic::Ordering::Relaxed)
                    + diff as isize;
                PEAK_LIVE_BYTES.fetch_max(live, core::sync::atomic::Ordering::Relaxed);
            } else if old_size > new_size {
                let diff = old_size - new_size;
                CURRENT_LIVE_BYTES.fetch_sub(diff as isize, core::sync::atomic::Ordering::Relaxed);
            }
        }
        new_ptr
    }
}

#[derive(Clone, Copy, Debug)]
struct BenchRunMetrics {
    elapsed: std::time::Duration,
    bytes_transferred: usize,
    allocs: u64,
    frees: u64,
    alloc_bytes: u64,
    peak_live_bytes: usize,
    pool_slots: usize,
}

impl core::fmt::Display for BenchRunMetrics {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:?} [allocs={}, frees={}, alloc_kib={}, peak_kib={}",
            self.elapsed,
            self.allocs,
            self.frees,
            self.alloc_bytes / 1024,
            self.peak_live_bytes / 1024,
        )?;
        if self.pool_slots > 0 {
            let pool_kib = (self.pool_slots * crate::DEFAULT_SLOT_SIZE) / 1024;
            write!(f, ", pool_slots={} ({} KiB)", self.pool_slots, pool_kib)?;
        }
        write!(f, "]")
    }
}

struct AllocMeasurement {
    base_allocs: u64,
    base_frees: u64,
    base_bytes_alloc: u64,
    base_live: isize,
}

impl AllocMeasurement {
    fn start() -> Self {
        let base_live = CURRENT_LIVE_BYTES.load(core::sync::atomic::Ordering::Relaxed);
        PEAK_LIVE_BYTES.store(base_live, core::sync::atomic::Ordering::Relaxed);
        Self {
            base_allocs: ALLOC_COUNT.load(core::sync::atomic::Ordering::Relaxed),
            base_frees: DEALLOC_COUNT.load(core::sync::atomic::Ordering::Relaxed),
            base_bytes_alloc: BYTES_ALLOCATED.load(core::sync::atomic::Ordering::Relaxed),
            base_live,
        }
    }

    fn finish(
        self,
        elapsed: std::time::Duration,
        bytes_transferred: usize,
        pool_slots: usize,
    ) -> BenchRunMetrics {
        let allocs = ALLOC_COUNT
            .load(core::sync::atomic::Ordering::Relaxed)
            .saturating_sub(self.base_allocs);
        let frees = DEALLOC_COUNT
            .load(core::sync::atomic::Ordering::Relaxed)
            .saturating_sub(self.base_frees);
        let alloc_bytes = BYTES_ALLOCATED
            .load(core::sync::atomic::Ordering::Relaxed)
            .saturating_sub(self.base_bytes_alloc);
        let peak_live = PEAK_LIVE_BYTES.load(core::sync::atomic::Ordering::Relaxed);
        let peak_delta = (peak_live - self.base_live).max(0) as usize;
        BenchRunMetrics {
            elapsed,
            bytes_transferred,
            allocs,
            frees,
            alloc_bytes,
            peak_live_bytes: peak_delta,
            pool_slots,
        }
    }
}

// ============================================================================
// Real `yamux` (v0.14) vs `TokioMux` (AsyncRead/Write & Zero-Copy) Benchmarks
// ============================================================================

trait AsyncReadWriteUnpin: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> AsyncReadWriteUnpin for T {}
type BoxedTransport = std::boxed::Box<dyn AsyncReadWriteUnpin>;

/// Benchmark real `yamux::Connection` (`yamux` v0.14) over 1..N byte-stream sockets.
///
/// Because Yamux cannot stripe a single connection across multiple sockets, when `N > 1`
/// streams are sharded round-robin across `N` independent `yamux::Connection` instances.
async fn run_real_yamux_over_streams(
    client_streams: Vec<BoxedTransport>,
    server_streams: Vec<BoxedTransport>,
    num_logical_streams: usize,
    chunks_per_stream: usize,
    payload_size: usize,
    buffered_io: bool,
) -> BenchRunMetrics {
    use futures_util::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_util::compat::TokioAsyncReadCompatExt as _;

    assert_eq!(client_streams.len(), server_streams.len());
    let num_conns = client_streams.len();
    let total_expected_bytes = num_logical_streams * chunks_per_stream * payload_size;
    let mem = AllocMeasurement::start();
    let start = std::time::Instant::now();

    let (done_tx, mut done_rx) =
        tokio::sync::mpsc::channel::<usize>(num_logical_streams.max(16));
    let mut server_conn_tasks = Vec::with_capacity(num_conns);

    for s_sock in server_streams {
        let s_sock: BoxedTransport = if buffered_io {
            std::boxed::Box::new(tokio::io::BufStream::with_capacity(
                64 * 1024,
                64 * 1024,
                s_sock,
            ))
        } else {
            s_sock
        };
        let mut server_conn = yamux::Connection::new(
            s_sock.compat(),
            yamux::Config::default(),
            yamux::Mode::Server,
        );
        let done_tx_conn = done_tx.clone();
        server_conn_tasks.push(tokio::spawn(async move {
            while let Some(res) =
                std::future::poll_fn(|cx| server_conn.poll_next_inbound(cx)).await
            {
                let Ok(mut stream) = res else {
                    break;
                };
                let done_tx_stream = done_tx_conn.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    let mut stream_bytes = 0usize;
                    loop {
                        let n = stream
                            .read(&mut buf)
                            .await
                            .expect("yamux server stream read failed");
                        if n == 0 {
                            break;
                        }
                        stream_bytes += n;
                    }
                    let _ = done_tx_stream.send(stream_bytes).await;
                });
            }
        }));
    }
    drop(done_tx);

    let (opened_tx, mut opened_rx) =
        tokio::sync::mpsc::channel::<yamux::Stream>(num_logical_streams.max(16));
    let mut client_close_txs = Vec::with_capacity(num_conns);
    let mut client_conn_tasks = Vec::with_capacity(num_conns);

    for (conn_idx, c_sock) in client_streams.into_iter().enumerate() {
        let streams_on_conn = (0..num_logical_streams)
            .filter(|s_idx| s_idx % num_conns == conn_idx)
            .count();
        let c_sock: BoxedTransport = if buffered_io {
            std::boxed::Box::new(tokio::io::BufStream::with_capacity(
                64 * 1024,
                64 * 1024,
                c_sock,
            ))
        } else {
            c_sock
        };
        let mut client_conn = yamux::Connection::new(
            c_sock.compat(),
            yamux::Config::default(),
            yamux::Mode::Client,
        );
        let (close_tx, mut close_rx) = tokio::sync::oneshot::channel::<()>();
        client_close_txs.push(close_tx);
        let opened_tx_conn = opened_tx.clone();

        client_conn_tasks.push(tokio::spawn(async move {
            let mut rem = streams_on_conn;
            while rem > 0 {
                let stream = std::future::poll_fn(|cx| {
                    if let std::task::Poll::Ready(Some(Err(e))) =
                        client_conn.poll_next_inbound(cx)
                    {
                        panic!("yamux client connection failed while opening streams: {e:?}");
                    }
                    client_conn.poll_new_outbound(cx)
                })
                .await
                .expect("yamux poll_new_outbound failed");
                rem -= 1;
                opened_tx_conn.send(stream).await.ok();
            }
            drop(opened_tx_conn);

            tokio::select! {
                _ = &mut close_rx => {
                    let _ = std::future::poll_fn(|cx| client_conn.poll_close(cx)).await;
                }
                _ = async {
                    while let Some(res) =
                        std::future::poll_fn(|cx| client_conn.poll_next_inbound(cx)).await
                    {
                        if res.is_err() {
                            break;
                        }
                    }
                } => {}
            }
        }));
    }
    drop(opened_tx);

    let payload = std::sync::Arc::new(vec![0x5au8; payload_size]);
    let mut writer_tasks = Vec::with_capacity(num_logical_streams);
    while let Some(mut stream) = opened_rx.recv().await {
        let payload_ref = payload.clone();
        writer_tasks.push(tokio::spawn(async move {
            for _ in 0..chunks_per_stream {
                stream
                    .write_all(&payload_ref)
                    .await
                    .expect("yamux stream write_all failed");
            }
            stream.close().await.expect("yamux stream close failed");
        }));
    }

    for wt in writer_tasks {
        wt.await.unwrap();
    }

    let mut total_rx = 0usize;
    let mut completed_streams = 0usize;
    while let Some(n) = done_rx.recv().await {
        assert_eq!(n, chunks_per_stream * payload_size);
        total_rx += n;
        completed_streams += 1;
        if completed_streams == num_logical_streams {
            break;
        }
    }
    assert_eq!(total_rx, total_expected_bytes);
    let elapsed = start.elapsed();
    let metrics = mem.finish(elapsed, total_rx, 0);

    for tx in client_close_txs {
        let _ = tx.send(());
    }
    for ct in client_conn_tasks {
        let _ = ct.await;
    }
    for st in server_conn_tasks {
        let _ = st.await;
    }
    metrics
}

/// Benchmark `TokioMux` + `MuxStream` using the exact same `AsyncRead + AsyncWrite` byte-stream
/// workload as `run_real_yamux_over_streams`.
async fn run_tokio_mux_async_io_stress(
    client_mux: crate::TokioMux,
    mut server_acceptor: crate::TokioMuxAcceptor,
    server_pool: SlabPool,
    num_logical_streams: usize,
    chunks_per_stream: usize,
    payload_size: usize,
) -> BenchRunMetrics {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let total_expected_bytes = num_logical_streams * chunks_per_stream * payload_size;
    let client_pool = client_mux.pool().clone();
    let mem = AllocMeasurement::start();
    let start = std::time::Instant::now();

    let (done_tx, mut done_rx) =
        tokio::sync::mpsc::channel::<usize>(num_logical_streams.max(16));
    let server_task = tokio::spawn(async move {
        while let Some(mut stream) = server_acceptor.accept().await {
            let done_tx_stream = done_tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let mut stream_bytes = 0usize;
                loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    stream_bytes += n;
                }
                let _ = done_tx_stream.send(stream_bytes).await;
            });
        }
    });

    let payload = std::sync::Arc::new(vec![0x5au8; payload_size]);
    let mut writer_tasks = Vec::with_capacity(num_logical_streams);
    for _ in 0..num_logical_streams {
        let cmux = client_mux.clone();
        let payload_ref = payload.clone();
        writer_tasks.push(tokio::spawn(async move {
            let mut stream = cmux.open_bidi().await.unwrap();
            for _ in 0..chunks_per_stream {
                stream.write_all(&payload_ref).await.unwrap();
            }
            stream.shutdown().await.unwrap();
        }));
    }

    for wt in writer_tasks {
        wt.await.unwrap();
    }

    let mut total_rx = 0usize;
    let mut completed_streams = 0usize;
    while let Some(n) = done_rx.recv().await {
        assert_eq!(n, chunks_per_stream * payload_size);
        total_rx += n;
        completed_streams += 1;
        if completed_streams == num_logical_streams {
            break;
        }
    }
    assert_eq!(total_rx, total_expected_bytes);
    let elapsed = start.elapsed();
    let pool_slots = client_pool.allocated() + server_pool.allocated();
    let metrics = mem.finish(elapsed, total_rx, pool_slots);

    client_mux.close();
    drop(client_mux);
    let _ = server_task.await;
    metrics
}

/// Benchmark `TokioMux` + `MuxStream` using the zero-copy `send_in_place` + `recv_chunks_drained` API
/// (single lock acquisition per send/receive burst, matching `AsyncWrite`/`AsyncRead` lock cadence
/// while writing directly into `XipLazyPacket` slots and consuming slices in-place).
async fn run_tokio_mux_zero_copy_stress(
    client_mux: crate::TokioMux,
    mut server_acceptor: crate::TokioMuxAcceptor,
    server_pool: SlabPool,
    num_logical_streams: usize,
    chunks_per_stream: usize,
    payload_size: usize,
) -> BenchRunMetrics {
    let total_expected_bytes = num_logical_streams * chunks_per_stream * payload_size;
    let client_pool = client_mux.pool().clone();
    let mem = AllocMeasurement::start();
    let start = std::time::Instant::now();

    let (done_tx, mut done_rx) =
        tokio::sync::mpsc::channel::<usize>(num_logical_streams.max(16));
    let server_task = tokio::spawn(async move {
        while let Some(mut stream) = server_acceptor.accept().await {
            let done_tx_stream = done_tx.clone();
            tokio::spawn(async move {
                let mut stream_bytes = 0usize;
                loop {
                    let n = stream.recv_chunks_drained(|_slice, _fin| {}).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    stream_bytes += n;
                }
                let _ = done_tx_stream.send(stream_bytes).await;
            });
        }
    });

    let mut writer_tasks = Vec::with_capacity(num_logical_streams);
    for _ in 0..num_logical_streams {
        let cmux = client_mux.clone();
        writer_tasks.push(tokio::spawn(async move {
            let mut stream = cmux.open_bidi().await.unwrap();
            for idx in 0..chunks_per_stream {
                let is_fin = idx + 1 == chunks_per_stream;
                stream
                    .send_in_place(is_fin, |slot| {
                        let send_len = payload_size.min(slot.len());
                        slot[..8].copy_from_slice(&(idx as u64).to_le_bytes());
                        send_len
                    })
                    .await
                    .unwrap();
            }
        }));
    }

    for wt in writer_tasks {
        wt.await.unwrap();
    }

    let mut total_rx = 0usize;
    let mut completed_streams = 0usize;
    while let Some(n) = done_rx.recv().await {
        assert_eq!(n, chunks_per_stream * payload_size);
        total_rx += n;
        completed_streams += 1;
        if completed_streams == num_logical_streams {
            break;
        }
    }
    assert_eq!(total_rx, total_expected_bytes);
    let elapsed = start.elapsed();
    let pool_slots = client_pool.allocated() + server_pool.allocated();
    let metrics = mem.finish(elapsed, total_rx, pool_slots);

    client_mux.close();
    drop(client_mux);
    let _ = server_task.await;
    metrics
}

fn bench_tokio_mux_config() -> crate::TokioMuxConfig {
    let pool = SlabPool::with_default_geometry(384);
    // Keep all 384 slots warm once allocated so mid-transfer bursts do not churn the heap,
    // and pre-warm 384 slots up front so steady-state transfer measures zero-alloc recycling.
    pool.set_keep(384);
    pool.prewarm(384);
    let mut cfg = crate::TokioMuxConfig {
        pool,
        rx_reserve_slots: 96,
        rx_channel_capacity: 128,
        default_tx_ring_capacity: 64,
        limits: MuxLimits::default(),
    };
    // Size `initial_max_data` (`256 KiB`) within `max_association_rx_packets` (`288` packets)
    // so multipath striping across heterogeneous TCP + UDS links can buffer a full window
    // out-of-order without triggering resource-pressure eviction.
    cfg.limits.initial_max_stream_data = 64 * 1024;
    cfg.limits.initial_max_data = 256 * 1024;
    cfg.limits.initial_max_streams_bidi = 128;
    cfg.limits.max_concurrent_streams = 128;
    cfg.limits.max_queued_chunks_per_stream = 128;
    cfg.limits.max_association_rx_packets = 288;
    cfg.limits.max_device_rx_packets = 288;
    cfg
}

async fn run_quic_mux_stress(
    mut client_links: crate::tokio_mux::TokioLinkSet,
    mut server_links: crate::tokio_mux::TokioLinkSet,
    client_pool: SlabPool,
    server_pool: SlabPool,
    num_logical_streams: usize,
    packets_per_stream: usize,
    payload_size: usize,
) -> BenchRunMetrics {
    let assoc = AssociationId(1);
    let limits = MuxLimits {
        initial_max_data: 256 * 1024,
        initial_max_stream_data: 64 * 1024,
        initial_max_streams_bidi: 128,
        max_concurrent_streams: 128,
        max_queued_chunks_per_stream: 128,
        max_association_rx_packets: 288,
        max_device_rx_packets: 288,
        ..MuxLimits::default()
    };

    let mut client_mux = QuicMux::new(client_pool.clone(), limits);
    let mut server_mux = QuicMux::new(server_pool.clone(), limits);
    client_mux.add_association(assoc, true).unwrap();
    server_mux.add_association(assoc, false).unwrap();

    let priorities = [
        StreamPriority::CRITICAL,
        StreamPriority::HIGH,
        StreamPriority::NORMAL,
        StreamPriority::BULK,
    ];
    let mut streams = Vec::with_capacity(num_logical_streams);
    for i in 0..num_logical_streams {
        streams.push(
            client_mux
                .open_stream_with_priority(assoc, true, priorities[i % priorities.len()])
                .unwrap(),
        );
    }

    let total_expected_bytes = num_logical_streams * packets_per_stream * payload_size;
    let mem = AllocMeasurement::start();
    let start = std::time::Instant::now();

    struct StressRxCallbacks {
        bytes_per_stream: std::collections::BTreeMap<StreamId, usize>,
        total_bytes: usize,
        fin_count: usize,
    }
    impl MuxCallbacks<SlabPacket> for StressRxCallbacks {
        fn on_stream_data(
            &mut self,
            _assoc: AssociationId,
            stream_id: StreamId,
            _offset: u64,
            chunk: RxStreamChunk<'_, SlabPacket>,
            fin: bool,
        ) -> Result<RxOutcome<SlabPacket>, StreamError> {
            let n = chunk.len();
            *self.bytes_per_stream.entry(stream_id).or_insert(0) += n;
            self.total_bytes += n;
            if fin {
                self.fin_count += 1;
            }
            Ok(RxOutcome::Consumed(n))
        }
    }

    let server_task = tokio::spawn(async move {
        let mut cb = StressRxCallbacks {
            bytes_per_stream: std::collections::BTreeMap::new(),
            total_bytes: 0,
            fin_count: 0,
        };
        while cb.total_bytes < total_expected_bytes || cb.fin_count < num_logical_streams {
            let Some(rx_pkt) = server_links.recv_packet().await else {
                break;
            };
            server_mux
                .receive_packet(
                    RxMeta {
                        association: rx_pkt.association,
                        received_at_us: 1_000,
                    },
                    rx_pkt.packet,
                    &mut server_links,
                    &mut cb,
                )
                .unwrap();
        }
        cb
    });

    let mut client_cb = StressRxCallbacks {
        bytes_per_stream: std::collections::BTreeMap::new(),
        total_bytes: 0,
        fin_count: 0,
    };

    let tx_notify = client_links.tx_space_notify().clone();
    for pkt_idx in 0..packets_per_stream {
        let is_fin = pkt_idx + 1 == packets_per_stream;
        for &sid in &streams {
            // Wait until flow-control + link space + pool slot are ready before allocating
            let mut pkt = loop {
                while let Some(rx_pkt) = client_links.try_recv_packet() {
                    client_mux
                        .receive_packet(
                            RxMeta {
                                association: rx_pkt.association,
                                received_at_us: 1_000,
                            },
                            rx_pkt.packet,
                            &mut client_links,
                            &mut client_cb,
                        )
                        .unwrap();
                }
                let notified = tx_notify.notified();
                let cap = client_mux
                    .stream_send_capacity(assoc, sid, &client_links)
                    .unwrap();
                if cap.can_send_now && cap.max_chunk_bytes >= payload_size {
                    if let Ok(p) = client_pool.alloc_reserving(64) {
                        break p;
                    }
                }
                notified.await;
            };
            {
                let h = client_pool.headroom();
                let slot = pkt.slot_slice_mut().unwrap();
                slot[h..h + 8].copy_from_slice(&(pkt_idx as u64).to_le_bytes());
                pkt.set_range(h..h + payload_size).unwrap();
            }

            loop {
                let notified = tx_notify.notified();
                match client_mux.write_stream(
                    assoc,
                    sid,
                    TxStreamData::Packet(pkt),
                    is_fin,
                    &mut client_links,
                ) {
                    Ok(_) => break,
                    Err(MuxSendError::Busy(Some(returned)))
                    | Err(MuxSendError::FlowControl(Some(returned))) => {
                        pkt = returned;
                        while let Some(rx_pkt) = client_links.try_recv_packet() {
                            client_mux
                                .receive_packet(
                                    RxMeta {
                                        association: rx_pkt.association,
                                        received_at_us: 1_000,
                                    },
                                    rx_pkt.packet,
                                    &mut client_links,
                                    &mut client_cb,
                                )
                                .unwrap();
                        }
                        notified.await;
                    }
                    Err(other) => panic!("unexpected send error: {other:?}"),
                }
            }
        }
    }

    let server_cb = server_task.await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(server_cb.total_bytes, total_expected_bytes);
    assert_eq!(server_cb.fin_count, num_logical_streams);
    for &sid in &streams {
        assert_eq!(
            server_cb.bytes_per_stream.get(&sid).copied(),
            Some(packets_per_stream * payload_size)
        );
    }
    let peak_slots = client_pool.allocated() + server_pool.allocated();
    mem.finish(elapsed, server_cb.total_bytes, peak_slots)
}

static BENCH_SERIAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tokio_perf_stress_single_tcp_and_uds_vs_yamux() {
    let _bench_guard = BENCH_SERIAL_LOCK.lock().unwrap();
    use crate::tokio_mux::TokioLinkSet;
    use crate::TokioMux;
    use tokio::net::{TcpListener, TcpStream, UnixDatagram, UnixStream};

    let assoc = AssociationId(1);
    let num_streams = 16;
    // 300 KiB per stream (> Yamux's 256 KiB DEFAULT_CREDIT) => 4,800 KiB total per transport,
    // exercising real flow-control window updates in both `yamux` and `quic-mux`.
    let packets_per_stream = 300;
    let payload_size = 1024;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept_tcp_pair = || async {
        let (c, s) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let c = c.unwrap();
        let (s, _) = s.unwrap();
        c.set_nodelay(true).unwrap();
        s.set_nodelay(true).unwrap();
        (c, s)
    };

    // 1. Single TCP link:
    //    (a) Low-level `QuicMux` + `TokioLinkSet` (64 KiB stream / 256 KiB assoc windows)
    //    (b) `TokioMux` Zero-Copy (`alloc_packet_async` + `send_packet` + `recv_chunk_coalesced`)
    //    (c) `TokioMux` `AsyncRead + AsyncWrite` (`MuxStream`)
    //    (d) Real `yamux::Connection` v0.14 (`yamux::Stream` `AsyncRead + AsyncWrite`, 256 KiB stream window)
    let (tcp_c1, tcp_s1) = accept_tcp_pair().await;
    let c_pool = SlabPool::with_default_geometry(384);
    let s_pool = SlabPool::with_default_geometry(384);
    c_pool.set_keep(384);
    s_pool.set_keep(384);
    c_pool.prewarm(384);
    s_pool.prewarm(384);
    let mut c_links = TokioLinkSet::new(c_pool.clone(), 128);
    let mut s_links = TokioLinkSet::new(s_pool.clone(), 128);
    c_links.add_stream_link(assoc, tcp_c1, 10, 64);
    s_links.add_stream_link(assoc, tcp_s1, 10, 64);
    let qmux_core_tcp = run_quic_mux_stress(
        c_links,
        s_links,
        c_pool.clone(),
        s_pool.clone(),
        num_streams,
        packets_per_stream,
        payload_size,
    )
    .await;

    let (tcp_zc_c, tcp_zc_s) = accept_tcp_pair().await;
    let (cmux_zc, _ca_zc) = TokioMux::client(tcp_zc_c, bench_tokio_mux_config());
    let (smux_zc, sa_zc) = TokioMux::server(tcp_zc_s, bench_tokio_mux_config());
    let smux_zc_pool = smux_zc.pool().clone();
    let tm_zc_tcp = run_tokio_mux_zero_copy_stress(
        cmux_zc,
        sa_zc,
        smux_zc_pool,
        num_streams,
        packets_per_stream,
        payload_size,
    )
    .await;
    drop(smux_zc);

    let (tcp_io_c, tcp_io_s) = accept_tcp_pair().await;
    let (cmux_io, _ca_io) = TokioMux::client(tcp_io_c, bench_tokio_mux_config());
    let (smux_io, sa_io) = TokioMux::server(tcp_io_s, bench_tokio_mux_config());
    let smux_io_pool = smux_io.pool().clone();
    let tm_io_tcp = run_tokio_mux_async_io_stress(
        cmux_io,
        sa_io,
        smux_io_pool,
        num_streams,
        packets_per_stream,
        payload_size,
    )
    .await;
    drop(smux_io);

    let (tcp_ym_c, tcp_ym_s) = accept_tcp_pair().await;
    let yamux_tcp = run_real_yamux_over_streams(
        vec![std::boxed::Box::new(tcp_ym_c)],
        vec![std::boxed::Box::new(tcp_ym_s)],
        num_streams,
        packets_per_stream,
        payload_size,
        false,
    )
    .await;

    let (tcp_ymb_c, tcp_ymb_s) = accept_tcp_pair().await;
    let yamux_buf_tcp = run_real_yamux_over_streams(
        vec![std::boxed::Box::new(tcp_ymb_c)],
        vec![std::boxed::Box::new(tcp_ymb_s)],
        num_streams,
        packets_per_stream,
        payload_size,
        true,
    )
    .await;

    // 2. Single UDS Stream (`UnixStream`): TokioMux Zero-Copy vs TokioMux AsyncIO vs Real Yamux
    let (uds_c1, uds_s1) = UnixStream::pair().unwrap();
    let mut c_uds_links = TokioLinkSet::new(c_pool.clone(), 128);
    let mut s_uds_links = TokioLinkSet::new(s_pool.clone(), 128);
    c_uds_links.add_stream_link(assoc, uds_c1, 10, 64);
    s_uds_links.add_stream_link(assoc, uds_s1, 10, 64);
    let qmux_core_uds = run_quic_mux_stress(
        c_uds_links,
        s_uds_links,
        c_pool.clone(),
        s_pool.clone(),
        num_streams,
        packets_per_stream,
        payload_size,
    )
    .await;

    let (uds_zc_c, uds_zc_s) = UnixStream::pair().unwrap();
    let (cmux_uds_zc, _) = TokioMux::client(uds_zc_c, bench_tokio_mux_config());
    let (smux_uds_zc, sa_uds_zc) = TokioMux::server(uds_zc_s, bench_tokio_mux_config());
    let smux_uds_zc_pool = smux_uds_zc.pool().clone();
    let tm_zc_uds = run_tokio_mux_zero_copy_stress(
        cmux_uds_zc,
        sa_uds_zc,
        smux_uds_zc_pool,
        num_streams,
        packets_per_stream,
        payload_size,
    )
    .await;
    drop(smux_uds_zc);

    let (uds_io_c, uds_io_s) = UnixStream::pair().unwrap();
    let (cmux_uds_io, _) = TokioMux::client(uds_io_c, bench_tokio_mux_config());
    let (smux_uds_io, sa_uds_io) = TokioMux::server(uds_io_s, bench_tokio_mux_config());
    let smux_uds_io_pool = smux_uds_io.pool().clone();
    let tm_io_uds = run_tokio_mux_async_io_stress(
        cmux_uds_io,
        sa_uds_io,
        smux_uds_io_pool,
        num_streams,
        packets_per_stream,
        payload_size,
    )
    .await;
    drop(smux_uds_io);

    let (uds_ym_c, uds_ym_s) = UnixStream::pair().unwrap();
    let yamux_uds = run_real_yamux_over_streams(
        vec![std::boxed::Box::new(uds_ym_c)],
        vec![std::boxed::Box::new(uds_ym_s)],
        num_streams,
        packets_per_stream,
        payload_size,
        false,
    )
    .await;

    let (uds_ymb_c, uds_ymb_s) = UnixStream::pair().unwrap();
    let yamux_buf_uds = run_real_yamux_over_streams(
        vec![std::boxed::Box::new(uds_ymb_c)],
        vec![std::boxed::Box::new(uds_ymb_s)],
        num_streams,
        packets_per_stream,
        payload_size,
        true,
    )
    .await;

    // 3. Single UDS Datagram (`UnixDatagram`): QuicMux packet mode (Yamux cannot run over datagrams)
    let (dgram_c, dgram_s) = UnixDatagram::pair().unwrap();
    let mut c_dgram_links = TokioLinkSet::new(c_pool.clone(), 128);
    let mut s_dgram_links = TokioLinkSet::new(s_pool.clone(), 128);
    c_dgram_links.add_datagram_link(assoc, dgram_c, 10, 64);
    s_dgram_links.add_datagram_link(assoc, dgram_s, 10, 64);
    let qmux_dgram = run_quic_mux_stress(
        c_dgram_links,
        s_dgram_links,
        c_pool.clone(),
        s_pool.clone(),
        num_streams,
        50,
        payload_size,
    )
    .await;

    tokio::task::yield_now().await;
    c_pool.set_keep(2);
    s_pool.set_keep(2);
    c_pool.trim();
    s_pool.trim();
    assert!(c_pool.allocated() <= 2 && s_pool.allocated() <= 2);

    std::eprintln!(
        "[single-link perf ({} KiB, 16 streams)]\n  TCP:\n    QuicMux-Core:        {}\n    TokioMux-ZeroCopy:   {}\n    TokioMux-AsyncIO:    {}\n    Real-Yamux:          {}\n    Real-Yamux(Buf64K):  {}\n  UDS-Stream:\n    QuicMux-Core:        {}\n    TokioMux-ZeroCopy:   {}\n    TokioMux-AsyncIO:    {}\n    Real-Yamux:          {}\n    Real-Yamux(Buf64K):  {}\n  UDS-Dgram (800 KiB):\n    QuicMux-Core:        {}",
        qmux_core_tcp.bytes_transferred / 1024,
        qmux_core_tcp,
        tm_zc_tcp,
        tm_io_tcp,
        yamux_tcp,
        yamux_buf_tcp,
        qmux_core_uds,
        tm_zc_uds,
        tm_io_uds,
        yamux_uds,
        yamux_buf_uds,
        qmux_dgram,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tokio_perf_stress_multipath_mixed_tcp_and_uds_streams() {
    let _bench_guard = BENCH_SERIAL_LOCK.lock().unwrap();
    use crate::tokio_mux::TokioLinkSet;
    use crate::TokioMux;
    use tokio::net::{TcpListener, TcpStream, UnixDatagram, UnixStream};

    let assoc = AssociationId(1);
    let num_streams = 16;
    let packets_per_stream = 300;
    let payload_size = 1024;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept_tcp_pair = || async {
        let (c, s) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let c = c.unwrap();
        let (s, _) = s.unwrap();
        c.set_nodelay(true).unwrap();
        s.set_nodelay(true).unwrap();
        (c, s)
    };

    // 1. Low-level `QuicMux` + `TokioLinkSet` bonding 2x TCP + 1x UDS-Stream in 1 association
    let (tcp_c1, tcp_s1) = accept_tcp_pair().await;
    let (tcp_c2, tcp_s2) = accept_tcp_pair().await;
    let (uds_c1, uds_s1) = UnixStream::pair().unwrap();

    let c_pool = SlabPool::with_default_geometry(384);
    let s_pool = SlabPool::with_default_geometry(384);
    c_pool.set_keep(384);
    s_pool.set_keep(384);
    c_pool.prewarm(384);
    s_pool.prewarm(384);

    let mut c_links = TokioLinkSet::new(c_pool.clone(), 128);
    let mut s_links = TokioLinkSet::new(s_pool.clone(), 128);
    c_links.add_stream_link(assoc, tcp_c1, 10, 32);
    c_links.add_stream_link(assoc, tcp_c2, 10, 32);
    c_links.add_stream_link(assoc, uds_c1, 10, 32);
    s_links.add_stream_link(assoc, tcp_s1, 10, 32);
    s_links.add_stream_link(assoc, tcp_s2, 10, 32);
    s_links.add_stream_link(assoc, uds_s1, 10, 32);

    let qmux_mp = run_quic_mux_stress(
        c_links,
        s_links,
        c_pool.clone(),
        s_pool.clone(),
        num_streams,
        packets_per_stream,
        payload_size,
    )
    .await;

    // 2. `TokioMux` Zero-Copy bonding 2x TCP + 1x UDS-Stream in 1 session
    let (zc_tc1, zc_ts1) = accept_tcp_pair().await;
    let (zc_tc2, zc_ts2) = accept_tcp_pair().await;
    let (zc_uc1, zc_us1) = UnixStream::pair().unwrap();
    let (cmux_zc, _) = TokioMux::spawn(true, bench_tokio_mux_config());
    let (smux_zc, sa_zc) = TokioMux::spawn(false, bench_tokio_mux_config());
    let smux_zc_pool = smux_zc.pool().clone();
    cmux_zc.add_tcp_link(zc_tc1, 10);
    cmux_zc.add_tcp_link(zc_tc2, 10);
    cmux_zc.add_uds_stream_link(zc_uc1, 10);
    smux_zc.add_tcp_link(zc_ts1, 10);
    smux_zc.add_tcp_link(zc_ts2, 10);
    smux_zc.add_uds_stream_link(zc_us1, 10);
    let tm_zc_mp = run_tokio_mux_zero_copy_stress(
        cmux_zc,
        sa_zc,
        smux_zc_pool,
        num_streams,
        packets_per_stream,
        payload_size,
    )
    .await;
    drop(smux_zc);

    // 3. `TokioMux` `AsyncRead + AsyncWrite` bonding 2x TCP + 1x UDS-Stream in 1 session
    let (io_tc1, io_ts1) = accept_tcp_pair().await;
    let (io_tc2, io_ts2) = accept_tcp_pair().await;
    let (io_uc1, io_us1) = UnixStream::pair().unwrap();
    let (cmux_io, _) = TokioMux::spawn(true, bench_tokio_mux_config());
    let (smux_io, sa_io) = TokioMux::spawn(false, bench_tokio_mux_config());
    let smux_io_pool = smux_io.pool().clone();
    cmux_io.add_tcp_link(io_tc1, 10);
    cmux_io.add_tcp_link(io_tc2, 10);
    cmux_io.add_uds_stream_link(io_uc1, 10);
    smux_io.add_tcp_link(io_ts1, 10);
    smux_io.add_tcp_link(io_ts2, 10);
    smux_io.add_uds_stream_link(io_us1, 10);
    let tm_io_mp = run_tokio_mux_async_io_stress(
        cmux_io,
        sa_io,
        smux_io_pool,
        num_streams,
        packets_per_stream,
        payload_size,
    )
    .await;
    drop(smux_io);

    // 4. Also test 1x TCP + 1x UnixStream + 1x UnixDatagram mixed in a single association!
    let (tcp_c3, tcp_s3) = accept_tcp_pair().await;
    let (uds_c2, uds_s2) = UnixStream::pair().unwrap();
    let (dgram_c, dgram_s) = UnixDatagram::pair().unwrap();

    let mut c_mix3 = TokioLinkSet::new(c_pool.clone(), 128);
    let mut s_mix3 = TokioLinkSet::new(s_pool.clone(), 128);
    c_mix3.add_stream_link(assoc, tcp_c3, 10, 32);
    c_mix3.add_stream_link(assoc, uds_c2, 10, 32);
    c_mix3.add_datagram_link(assoc, dgram_c, 10, 32);
    s_mix3.add_stream_link(assoc, tcp_s3, 10, 32);
    s_mix3.add_stream_link(assoc, uds_s2, 10, 32);
    s_mix3.add_datagram_link(assoc, dgram_s, 10, 32);

    let qmux_dgram_mix = run_quic_mux_stress(
        c_mix3,
        s_mix3,
        c_pool.clone(),
        s_pool.clone(),
        num_streams,
        60,
        payload_size,
    )
    .await;

    // 5. Real `yamux::Connection` v0.14 over the exact same `2x TCP + 1x UDS-Stream` sockets
    //    (sharded across 3 independent `yamux::Connection`s since Yamux cannot bond links)
    let (ym_tc1, ym_ts1) = accept_tcp_pair().await;
    let (ym_tc2, ym_ts2) = accept_tcp_pair().await;
    let (ym_uc1, ym_us1) = UnixStream::pair().unwrap();
    let yamux_mp = run_real_yamux_over_streams(
        vec![
            std::boxed::Box::new(ym_tc1),
            std::boxed::Box::new(ym_tc2),
            std::boxed::Box::new(ym_uc1),
        ],
        vec![
            std::boxed::Box::new(ym_ts1),
            std::boxed::Box::new(ym_ts2),
            std::boxed::Box::new(ym_us1),
        ],
        num_streams,
        packets_per_stream,
        payload_size,
        true,
    )
    .await;

    std::eprintln!(
        "[multipath 3-link perf ({} KiB, 2xTCP + 1xUDS-Stream)]\n  QuicMux-Core:                {}\n  TokioMux-ZeroCopy:           {}\n  TokioMux-AsyncIO:            {}\n  Real-Yamux-Sharded(Buf64K):  {}\n  QuicMux-Core (960 KiB, 1xTCP + 1xUDS-Stream + 1xUDS-Dgram):\n    {}",
        qmux_mp.bytes_transferred / 1024,
        qmux_mp,
        tm_zc_mp,
        tm_io_mp,
        yamux_mp,
        qmux_dgram_mix,
    );
}

#[test]
fn tx_small_packet_coalescing_and_rx_half_mtu_split_ownership() {
    use crate::{default_coalesce_threshold, try_coalesce_tx_packet};

    let pool = SlabPool::with_default_geometry(16);
    let mut tx_mux = QuicMux::new(pool.clone(), MuxLimits::default());
    let mut rx_mux = QuicMux::new(pool.clone(), MuxLimits::default());

    let assoc = AssociationId(11);
    tx_mux.add_association(assoc, true).unwrap();
    rx_mux.add_association(assoc, false).unwrap();

    let s_large = tx_mux
        .open_stream_with_priority(assoc, true, StreamPriority::HIGH)
        .unwrap();
    let s_in_order = tx_mux
        .open_stream_with_priority(assoc, true, StreamPriority::NORMAL)
        .unwrap();
    let s_ooo = tx_mux
        .open_stream_with_priority(assoc, true, StreamPriority::LOW)
        .unwrap();

    let mtu = 1500usize;
    let coalesce_thresh = default_coalesce_threshold(mtu);
    assert_eq!(coalesce_thresh, 500);

    let mut links = CostOrderedLinks::new(mtu);

    // 1. Prepare a 900-byte (`> 1/2 MTU`) zero-copy packet on `s_large`
    let mut large_pkt = pool.alloc().unwrap();
    let large_payload: Vec<u8> = (0..900).map(|i| (i % 251) as u8).collect();
    large_pkt.append(&large_payload).unwrap();
    tx_mux
        .write_stream(
            assoc,
            s_large,
            TxStreamData::Packet(large_pkt),
            true,
            &mut links,
        )
        .unwrap();

    // 2. Prepare a 24-byte (`< 1/3 MTU`) in-order packet on `s_in_order`
    tx_mux
        .write_stream(
            assoc,
            s_in_order,
            TxStreamData::Bytes(b"small-in-order-greeting!"),
            true,
            &mut links,
        )
        .unwrap();

    // 3. Prepare 2 small packets on `s_ooo` (hold packet #1 back so packet #2 arrives out-of-order!)
    tx_mux
        .write_stream(assoc, s_ooo, TxStreamData::Bytes(b"0123456789"), false, &mut links)
        .unwrap();
    tx_mux
        .write_stream(
            assoc,
            s_ooo,
            TxStreamData::Bytes(b"small-ooo-payload!"),
            true,
            &mut links,
        )
        .unwrap();

    let (mut head_meta, mut head_pkt) = links.link0_sent.pop_front().unwrap();
    let (in_order_meta, in_order_pkt) = links.link0_sent.pop_front().unwrap();
    let (_ooo_first_meta, ooo_first_pkt) = links.link0_sent.pop_front().unwrap();
    let (ooo_second_meta, ooo_second_pkt) = links.link0_sent.pop_front().unwrap();

    // Link layer coalesces both `< 1/3 MTU` packets onto `head_pkt` in-place, immediately freeing their pool slots!
    assert_eq!(pool.available(), 12);
    try_coalesce_tx_packet(
        &mut head_meta,
        &mut head_pkt,
        in_order_meta,
        in_order_pkt,
        mtu,
        coalesce_thresh,
    )
    .expect("24B packet (< 1/3 MTU) coalesces into pending packet");
    assert_eq!(pool.available(), 13);

    try_coalesce_tx_packet(
        &mut head_meta,
        &mut head_pkt,
        ooo_second_meta,
        ooo_second_pkt,
        mtu,
        coalesce_thresh,
    )
    .expect("18B packet (< 1/3 MTU) coalesces into pending packet");
    assert_eq!(pool.available(), 14);
    assert_eq!(head_meta.stream_id, None);
    assert_eq!(head_meta.priority, StreamPriority::HIGH);

    // Verify packets `> 1/3 MTU` are refused by `try_coalesce_tx_packet` without mutation
    let mut big_probe = pool.alloc().unwrap();
    big_probe.append(&[0xAB; 600]).unwrap();
    let big_probe = try_coalesce_tx_packet(
        &mut head_meta,
        &mut head_pkt,
        TxPacketMeta {
            association: assoc,
            stream_id: Some(s_large),
            priority: StreamPriority::LOW,
            retransmittable: true,
        },
        big_probe,
        mtu,
        coalesce_thresh,
    )
    .expect_err("600B packet (> 1/3 MTU) must not be coalesced");
    drop(big_probe);
    assert_eq!(pool.available(), 14);

    // Custom callback inspecting ownership (`packet: Some` vs `small_buf`)
    struct OwnershipCheckCb {
        owned_chunks: Vec<(StreamId, Vec<u8>, SlabPacket)>,
        slice_chunks: Vec<(StreamId, Vec<u8>, bool)>,
    }
    impl MuxCallbacks<SlabPacket> for OwnershipCheckCb {
        fn on_stream_data(
            &mut self,
            _assoc: AssociationId,
            stream_id: StreamId,
            _offset: u64,
            mut chunk: RxStreamChunk<'_, SlabPacket>,
            fin: bool,
        ) -> Result<RxOutcome<SlabPacket>, StreamError> {
            let bytes = chunk.bytes().to_vec();
            if let Some(pkt) = chunk.take_packet() {
                assert!(
                    pkt.is_unique(),
                    "> 1/2 MTU frame must receive exclusive PoolPacket ownership (refs == 1)"
                );
                self.owned_chunks.push((stream_id, bytes, pkt));
            } else {
                self.slice_chunks.push((stream_id, bytes, fin));
            }
            Ok(RxOutcome::Consumed(chunk.small_buf.len().max(
                self.owned_chunks.last().map_or(0, |c| c.1.len()),
            )))
        }
    }

    let mut cb = OwnershipCheckCb {
        owned_chunks: Vec::new(),
        slice_chunks: Vec::new(),
    };

    // Deliver the combined packet `[900B s_large | 24B s_in_order | 18B s_ooo(offset=10)]`
    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 1_000,
            },
            head_pkt,
            &mut links,
            &mut cb,
        )
        .unwrap();

    // `s_large` (900B > 750B half-MTU) got exclusive PoolPacket ownership!
    assert_eq!(cb.owned_chunks.len(), 1);
    assert_eq!(cb.owned_chunks[0].0, s_large);
    assert_eq!(cb.owned_chunks[0].1, large_payload);
    assert!(cb.owned_chunks[0].2.is_unique());

    // `s_in_order` (24B <= 750B) was copied to a small buffer and delivered as a slice!
    assert_eq!(cb.slice_chunks.len(), 1);
    assert_eq!(
        cb.slice_chunks[0],
        (s_in_order, b"small-in-order-greeting!".to_vec(), true)
    );

    // Drop the owned `s_large` packet: even though `s_ooo` still has 18 out-of-order bytes queued
    // in `rx_mux`, ZERO pool slots are pinned by `rx_mux` (only `ooo_first_pkt` is still allocated)!
    cb.owned_chunks.clear();
    assert_eq!(rx_mux.total_rx_queued_packets(), 1);
    assert_eq!(pool.available(), 15);

    // Now deliver `ooo_first_pkt` (offset 0..10 on `s_ooo`): both chunks complete in order!
    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 1_500,
            },
            ooo_first_pkt,
            &mut links,
            &mut cb,
        )
        .unwrap();
    assert_eq!(rx_mux.total_rx_queued_packets(), 0);
    assert_eq!(cb.owned_chunks.len(), 1);
    assert_eq!(cb.owned_chunks[0].0, s_ooo);
    assert_eq!(cb.owned_chunks[0].1, b"0123456789".to_vec());
    assert_eq!(cb.slice_chunks.len(), 2);
    assert_eq!(
        cb.slice_chunks[1],
        (s_ooo, b"small-ooo-payload!".to_vec(), true)
    );
    cb.owned_chunks.clear();
    assert_eq!(pool.available(), 16);

    // Finally, verify a multi-frame packet where ALL frames are `<= 1/2 MTU` frees the pool slot immediately
    let s_a = tx_mux.open_stream(assoc, true).unwrap();
    let s_b = tx_mux.open_stream(assoc, true).unwrap();
    tx_mux
        .write_stream(assoc, s_a, TxStreamData::Bytes(&[0x11; 120]), true, &mut links)
        .unwrap();
    tx_mux
        .write_stream(assoc, s_b, TxStreamData::Bytes(&[0x22; 140]), true, &mut links)
        .unwrap();
    let (mut m_a, mut p_a) = links.link0_sent.pop_front().unwrap();
    let (m_b, p_b) = links.link0_sent.pop_front().unwrap();
    try_coalesce_tx_packet(&mut m_a, &mut p_a, m_b, p_b, mtu, coalesce_thresh).unwrap();

    rx_mux
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 2_000,
            },
            p_a,
            &mut links,
            &mut cb,
        )
        .unwrap();
    assert!(cb.owned_chunks.is_empty());
    assert_eq!(cb.slice_chunks.len(), 4);
    assert_eq!(pool.available(), 16);
}

#[tokio::test]
async fn tokio_mux_stream_tcp_substitute_and_stream_churn() {
    use crate::{TokioMux, TokioMuxConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UnixStream};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tcp_c, tcp_s) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let tcp_c = tcp_c.unwrap();
    let (tcp_s, _) = tcp_s.unwrap();
    let (uds_c, uds_s) = UnixStream::pair().unwrap();

    // Tight MAX_STREAMS = 8 limit so opening 64 sequential streams proves `close_stream` + `MAX_STREAMS_BIDI` credit replenishment!
    let mut cfg = TokioMuxConfig::default();
    cfg.limits.initial_max_streams_bidi = 8;
    cfg.limits.max_concurrent_streams = 8;

    let (client_mux, _client_acceptor) = TokioMux::spawn(true, cfg.clone());
    let (server_mux, mut server_acceptor) = TokioMux::spawn(false, cfg);

    client_mux.add_tcp_link(tcp_c, 10);
    client_mux.add_uds_stream_link(uds_c, 10);
    server_mux.add_tcp_link(tcp_s, 10);
    server_mux.add_uds_stream_link(uds_s, 10);

    // Server loop looks identical to a `TcpListener::accept` echo server using `tokio::io::copy`!
    let server_task = tokio::spawn(async move {
        while let Some(stream) = server_acceptor.accept().await {
            tokio::spawn(async move {
                let (mut rd, mut wr) = stream.into_split();
                tokio::io::copy(&mut rd, &mut wr).await.unwrap();
                wr.shutdown().await.unwrap();
            });
        }
    });

    // 1. Churn 64 sequential request/response streams over an 8-stream limit!
    for i in 0..64u32 {
        let mut s = client_mux.open_bidi().await.unwrap();
        let msg = alloc::format!("request-number-{i:04}-payload");
        s.write_all(msg.as_bytes()).await.unwrap();
        s.shutdown().await.unwrap();

        let mut echoed = Vec::new();
        s.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, msg.as_bytes());
    }

    // 2. Concurrent small writes across 8 streams to trigger TX `< 1/3 MTU` coalescing!
    let mut tasks = Vec::new();
    for task_idx in 0..8u8 {
        let cmux = client_mux.clone();
        tasks.push(tokio::spawn(async move {
            let mut s = cmux.open_bidi().await.unwrap();
            let mut expected = Vec::new();
            for chunk_idx in 0..32u8 {
                let piece = [task_idx ^ chunk_idx; 24];
                s.write_all(&piece).await.unwrap();
                expected.extend_from_slice(&piece);
            }
            s.shutdown().await.unwrap();
            let mut actual = Vec::new();
            s.read_to_end(&mut actual).await.unwrap();
            assert_eq!(actual, expected);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }

    let coalesced = client_mux.coalesced_tx_packets() + server_mux.coalesced_tx_packets();
    assert!(
        coalesced > 0,
        "expected small concurrent writes (< 1/3 MTU) to coalesce while links had pending packets"
    );

    drop(client_mux);
    drop(_client_acceptor);
    drop(server_mux);
    let _ = server_task.await;
}

#[tokio::test]
async fn tokio_mux_zero_copy_packet_ownership_and_hybrid_gateway_proxy() {
    use crate::{TokioMux, TokioMuxConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UnixStream};

    // Topology: Client <--(UDS TokioMux #1)--> Gateway <--(TCP TokioMux #2)--> Backend
    let (uds_client, uds_gw) = UnixStream::pair().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tcp_gw, tcp_backend) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let tcp_gw = tcp_gw.unwrap();
    let (tcp_backend, _) = tcp_backend.unwrap();

    // Gateway shares ONE packet pool across both its inbound UDS mux and outbound TCP mux
    // so packets received on UDS are forwarded directly onto TCP with zero copies!
    let gw_shared_cfg = TokioMuxConfig::default();
    let (client_mux, _c_acc) = TokioMux::client(uds_client, TokioMuxConfig::default());
    let (_gw_in_mux, mut gw_in_acc) = TokioMux::server(uds_gw, gw_shared_cfg.clone());
    let (gw_out_mux, _gw_out_acc) = TokioMux::client(tcp_gw, gw_shared_cfg);
    let (_backend_mux, mut backend_acc) =
        TokioMux::server(tcp_backend, TokioMuxConfig::default());

    // Gateway task: reads 16-byte routing header via `AsyncRead`, then splices body zero-copy via `recv_chunk` + `send_packet`!
    let gw_task = tokio::spawn(async move {
        let mut inbound = gw_in_acc.accept().await.unwrap();
        let mut route_hdr = [0u8; 16];
        inbound.read_exact(&mut route_hdr).await.unwrap();
        assert_eq!(&route_hdr, b"ROUTE:backend-01");

        let mut outbound = gw_out_mux.open_bidi().await.unwrap();
        let mut zero_copy_packets_forwarded = 0usize;

        while let Some(mut chunk) = inbound.recv_chunk().await.unwrap() {
            let fin = chunk.is_fin();
            if let Some(pkt) = chunk.take_packet() {
                assert!(pkt.is_unique());
                outbound.send_packet(pkt, fin).await.unwrap();
                zero_copy_packets_forwarded += 1;
            } else {
                outbound.write_all(chunk.bytes()).await.unwrap();
                if fin {
                    outbound.finish().await.unwrap();
                }
            }
        }
        assert_eq!(zero_copy_packets_forwarded, 5);

        // Also forward backend's zero-copy reply back to client
        while let Some(mut reply_chunk) = outbound.recv_chunk().await.unwrap() {
            let fin = reply_chunk.is_fin();
            if let Some(pkt) = reply_chunk.take_packet() {
                inbound.send_packet(pkt, fin).await.unwrap();
            } else {
                inbound.write_all(reply_chunk.bytes()).await.unwrap();
                if fin {
                    inbound.finish().await.unwrap();
                }
            }
        }
    });

    // Backend task: receives zero-copy chunks, verifies data, and replies with a zero-copy packet
    let backend_task = tokio::spawn(async move {
        let mut stream = backend_acc.accept().await.unwrap();
        let mut received_body = Vec::new();
        while let Some(mut chunk) = stream.recv_chunk().await.unwrap() {
            assert!(chunk.is_packet_owned());
            let pkt = chunk.take_packet().unwrap();
            received_body.extend_from_slice(pkt.bytes());
        }
        assert_eq!(received_body.len(), 1100 + 4 * 1200);
        for (idx, &b) in received_body.iter().enumerate() {
            assert_eq!(b, ((idx * 7 + 3) % 251) as u8);
        }

        let mut reply_pkt = stream.alloc_packet().unwrap();
        reply_pkt.append(b"BACKEND-ZERO-COPY-ACK-OK").unwrap();
        stream.send_packet(reply_pkt, true).await.unwrap();
    });

    // Client: sends 5 pool packets (first packet prepends the 16-byte routing header + 1100B body; next 4 carry 1200B each)
    let mut c_stream = client_mux.open_bidi().await.unwrap();
    let total_body_len = 1100 + 4 * 1200;
    let full_body: Vec<u8> = (0..total_body_len)
        .map(|i| ((i * 7 + 3) % 251) as u8)
        .collect();

    let mut pkt0 = c_stream.alloc_packet().unwrap();
    pkt0.append(b"ROUTE:backend-01").unwrap();
    pkt0.append(&full_body[..1100]).unwrap();
    c_stream.send_packet(pkt0, false).await.unwrap();

    for i in 0..4 {
        let start = 1100 + i * 1200;
        let end = start + 1200;
        let mut pkt = c_stream.alloc_packet().unwrap();
        pkt.append(&full_body[start..end]).unwrap();
        c_stream.send_packet(pkt, i == 3).await.unwrap();
    }

    let mut ack = Vec::new();
    c_stream.read_to_end(&mut ack).await.unwrap();
    assert_eq!(ack, b"BACKEND-ZERO-COPY-ACK-OK");

    gw_task.await.unwrap();
    backend_task.await.unwrap();
}

#[test]
fn frame_wire_order_packet_atomic_and_connection_close_variants() {
    use crate::wire::{
        Frame, WireError, decode_frame, encode_control_frame, encode_stream_header, encode_varint,
    };

    // 1. Varint frame type > 255 preserves the full 62-bit varint in `UnsupportedFrame`.
    let mut unknown_buf = [0u8; 8];
    let n_unk = encode_varint(0x1234, &mut unknown_buf).unwrap();
    assert_eq!(
        decode_frame(&unknown_buf[..n_unk], 0),
        Err(WireError::UnsupportedFrame(0x1234))
    );

    let pool = SlabPool::with_default_geometry(16);
    let mut client = QuicMux::new(pool.clone(), MuxLimits::default());
    let mut server = QuicMux::new(pool.clone(), MuxLimits::default());
    let assoc = AssociationId(11);
    client.add_association(assoc, true).unwrap();
    server.add_association(assoc, false).unwrap();
    let mut links = CostOrderedLinks::new(1400);
    let mut cb = RecordingCallbacks::default();

    // 2. `[STREAM("abc"), RESET_STREAM(final_size=3)]` in ONE packet delivers `"abc"` first, THEN resets.
    let s0 = client.open_stream(assoc, true).unwrap();
    let mut pkt_a = pool.alloc().unwrap();
    let mut raw_a = [0u8; 64];
    let mut at = encode_stream_header(s0, 0, 3, false, true, &mut raw_a).unwrap();
    raw_a[at..at + 3].copy_from_slice(b"abc");
    at += 3;
    at += encode_control_frame(
        &Frame::ResetStream {
            stream_id: s0,
            error_code: 77,
            final_size: 3,
        },
        &mut raw_a[at..],
    )
    .unwrap();
    pkt_a.append(&raw_a[..at]).unwrap();
    server
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 10,
            },
            pkt_a,
            &mut links,
            &mut cb,
        )
        .unwrap();
    assert_eq!(cb.received.len(), 1);
    assert_eq!(cb.received[0].3, b"abc");
    assert_eq!(
        cb.closed_streams,
        vec![(
            assoc,
            s0,
            StreamCloseReason::PeerReset {
                error_code: 77,
                final_size: 3,
            }
        )]
    );
    cb.received.clear();
    cb.closed_streams.clear();
    cb.forwarded_packets.clear();

    // 3. Inverted wire order `[RESET_STREAM(final_size=3), STREAM("xyz")]` resets FIRST and ignores trailing STREAM!
    let s1 = client.open_stream(assoc, true).unwrap();
    let mut pkt_b = pool.alloc().unwrap();
    let mut raw_b = [0u8; 64];
    let mut at_b = encode_control_frame(
        &Frame::ResetStream {
            stream_id: s1,
            error_code: 88,
            final_size: 3,
        },
        &mut raw_b,
    )
    .unwrap();
    let sh = encode_stream_header(s1, 0, 3, false, true, &mut raw_b[at_b..]).unwrap();
    at_b += sh;
    raw_b[at_b..at_b + 3].copy_from_slice(b"xyz");
    at_b += 3;
    pkt_b.append(&raw_b[..at_b]).unwrap();
    server
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 20,
            },
            pkt_b,
            &mut links,
            &mut cb,
        )
        .unwrap();
    assert!(
        cb.received.is_empty(),
        "trailing STREAM after RESET_STREAM must not deliver bytes"
    );
    assert_eq!(cb.closed_streams.len(), 1);
    cb.closed_streams.clear();

    // 4. Packet-atomic malformed frame policy: valid `[MAX_DATA, STREAM]` followed by truncated `0x04`
    // rejects the entire packet with ZERO partial state mutation.
    let s2 = client.open_stream(assoc, true).unwrap();
    let mut pkt_bad = pool.alloc().unwrap();
    let mut raw_bad = [0u8; 64];
    let mut at_bad = encode_control_frame(&Frame::MaxData(999_999), &mut raw_bad).unwrap();
    at_bad += encode_stream_header(s2, 0, 4, false, true, &mut raw_bad[at_bad..]).unwrap();
    raw_bad[at_bad..at_bad + 4].copy_from_slice(b"atom");
    at_bad += 4;
    raw_bad[at_bad] = 0x04; // truncated RESET_STREAM
    at_bad += 1;
    pkt_bad.append(&raw_bad[..at_bad]).unwrap();
    assert_eq!(
        server.receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 30,
            },
            pkt_bad,
            &mut links,
            &mut cb,
        ),
        Err(crate::MuxError::Wire(WireError::UnexpectedEof))
    );
    assert!(cb.received.is_empty());
    assert_eq!(
        server
            .stream_send_capacity(assoc, s0, &links)
            .map(|c| c.association_window),
        Ok(MuxLimits::default().initial_max_data)
    );

    // 5. Both transport (`0x1c`, `is_application == false`) and application (`0x1d`, `is_application == true`)
    // `CONNECTION_CLOSE` round-trip via `close_association`.
    links.link0_sent.clear();
    client
        .close_association(assoc, false, 0x0a, 0x08, &mut links)
        .unwrap();
    client
        .close_association(assoc, true, 0x42, 0, &mut links)
        .unwrap();
    assert_eq!(links.link0_sent.len(), 2);
    let (_, cc_trans) = links.link0_sent.pop_front().unwrap();
    let (_, cc_app) = links.link0_sent.pop_front().unwrap();
    assert_eq!(cc_trans.bytes()[0], 0x1c);
    assert_eq!(cc_app.bytes()[0], 0x1d);

    server
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 40,
            },
            cc_trans,
            &mut links,
            &mut cb,
        )
        .unwrap();
    server
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 50,
            },
            cc_app,
            &mut links,
            &mut cb,
        )
        .unwrap();
    assert_eq!(
        cb.broken_associations,
        vec![
            (
                assoc,
                AssociationBrokenReason::PeerConnectionClose {
                    is_application: false,
                    error_code: 0x0a,
                    frame_type: 0x08,
                }
            ),
            (
                assoc,
                AssociationBrokenReason::PeerConnectionClose {
                    is_application: true,
                    error_code: 0x42,
                    frame_type: 0,
                }
            ),
        ]
    );
}

#[test]
fn untrusted_peer_stream_limits_directions_and_anti_resurrection() {
    use crate::MuxError;
    use crate::wire::{Frame, encode_control_frame, encode_stream_header};

    let pool = SlabPool::with_default_geometry(16);
    let limits = MuxLimits {
        initial_max_data: 64,
        initial_max_stream_data: 16,
        initial_max_streams_bidi: 2,
        initial_max_streams_uni: 1,
        max_concurrent_streams: 4,
        ..MuxLimits::default()
    };
    let mut client = QuicMux::new(pool.clone(), limits);
    let mut server = QuicMux::new(pool.clone(), limits);
    let assoc = AssociationId(21);
    client.add_association(assoc, true).unwrap();
    server.add_association(assoc, false).unwrap();

    let mut links = CostOrderedLinks::new(1200);
    let mut cb = RecordingCallbacks::default();

    let make_stream_pkt = |sid: StreamId, off: u64, payload: &[u8], fin: bool| {
        let mut p = pool.alloc().unwrap();
        let mut h = [0u8; 32];
        let n = encode_stream_header(sid, off, payload.len(), fin, true, &mut h).unwrap();
        p.append(&h[..n]).unwrap();
        p.append(payload).unwrap();
        p
    };

    // 1. Server cannot open a client-initiated stream ID (`StreamId(0)` sent to client -> wrong initiator bit!).
    let wrong_init_pkt = make_stream_pkt(StreamId(0), 0, b"bad", false);
    assert_eq!(
        client.receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 10
            },
            wrong_init_pkt,
            &mut links,
            &mut cb
        ),
        Err(MuxError::InvalidStreamState)
    );

    // 2. Peer cannot send `STREAM` or `RESET_STREAM` on a locally-initiated unidirectional stream (`StreamId(2)`).
    let local_uni = client.open_stream(assoc, false).unwrap();
    assert_eq!(local_uni, StreamId(2));
    let illegal_uni_rx = make_stream_pkt(local_uni, 0, b"nope", false);
    assert_eq!(
        client.receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 20
            },
            illegal_uni_rx,
            &mut links,
            &mut cb
        ),
        Err(MuxError::InvalidStreamState)
    );

    // 3. Peer cannot send `STOP_SENDING` or `MAX_STREAM_DATA` on a peer-initiated unidirectional stream (`StreamId(3)`).
    let peer_uni = server.open_stream(assoc, false).unwrap();
    assert_eq!(peer_uni, StreamId(3));
    let mut bad_stop = pool.alloc().unwrap();
    let mut cbuf = [0u8; 32];
    let cn = encode_control_frame(
        &Frame::StopSending {
            stream_id: peer_uni,
            error_code: 1,
        },
        &mut cbuf,
    )
    .unwrap();
    bad_stop.append(&cbuf[..cn]).unwrap();
    assert_eq!(
        client.receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 30
            },
            bad_stop,
            &mut links,
            &mut cb
        ),
        Err(MuxError::InvalidStreamState)
    );

    // 4. Peer exceeding `initial_max_streams_bidi = 2` (`StreamId(8)` has index 2 >= 2) is rejected!
    let over_limit_bidi = make_stream_pkt(StreamId(8), 0, b"hi", false);
    assert_eq!(
        server.receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 40
            },
            over_limit_bidi,
            &mut links,
            &mut cb
        ),
        Err(MuxError::StreamLimitReached)
    );

    // 5. Initial `STREAM` frame violating `initial_max_stream_data = 16` is rejected BEFORE inserting stream!
    let over_fc = make_stream_pkt(StreamId(0), 10, b"0123456789", false); // end_offset = 20 > 16
    assert_eq!(
        server.receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 50
            },
            over_fc,
            &mut links,
            &mut cb
        ),
        Err(MuxError::FlowControlViolation)
    );
    // Verify `StreamId(0)` was NOT inserted by the failed frame: valid `StreamId(0)` & `StreamId(4)` both still open cleanly!
    let valid_s0 = make_stream_pkt(StreamId(0), 0, b"ok0", true);
    server
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 60,
            },
            valid_s0,
            &mut links,
            &mut cb,
        )
        .unwrap();
    cb.forwarded_packets.clear();
    assert!(server.close_stream(assoc, StreamId(0), &mut links));

    // 6. Anti-resurrection: late `STREAM` frame for already-closed `StreamId(0)` is ignored without re-creating `StreamId(0)`!
    cb.received.clear();
    let late_s0 = make_stream_pkt(StreamId(0), 0, b"ghost", false);
    server
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 70,
            },
            late_s0,
            &mut links,
            &mut cb,
        )
        .unwrap();
    assert!(cb.received.is_empty());
    assert_eq!(
        server.stream_priority(assoc, StreamId(0)),
        Err(MuxError::UnknownStream)
    );
}

#[test]
fn stop_sending_and_reset_stream_final_size_and_credit_reclamation() {
    use crate::MuxError;
    use crate::wire::{Frame, decode_frame, encode_control_frame, encode_stream_header};

    let pool = SlabPool::with_default_geometry(16);
    let limits = MuxLimits {
        initial_max_data: 32,
        initial_max_stream_data: 16,
        initial_max_streams_bidi: 16,
        ..MuxLimits::default()
    };
    let mut client = QuicMux::new(pool.clone(), limits);
    let mut server = QuicMux::new(pool.clone(), limits);
    let assoc = AssociationId(31);
    client.add_association(assoc, true).unwrap();
    server.add_association(assoc, false).unwrap();

    let mut links = CostOrderedLinks::new(1200);
    let mut client_cb = RecordingCallbacks::default();
    let mut server_cb = RecordingCallbacks::default();

    // 1. Peer sends `STOP_SENDING`: local sender stops (`MuxError::StreamReset`), aborts TX, and replies with `RESET_STREAM`.
    let s0 = client.open_stream(assoc, true).unwrap();
    client
        .write_stream(assoc, s0, TxStreamData::Bytes(b"12345"), false, &mut links)
        .unwrap();
    let (_, data_pkt) = links.link0_sent.pop_front().unwrap();
    server
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 10,
            },
            data_pkt,
            &mut links,
            &mut server_cb,
        )
        .unwrap();
    server_cb.forwarded_packets.clear();
    links.link0_sent.clear();
    links.aborted_streams.clear();

    assert!(server.stop_sending(assoc, s0, 0x99, &mut links));
    let (_, stop_pkt) = links.link0_sent.pop_front().unwrap();
    client
        .receive_packet(
            RxMeta {
                association: assoc,
                received_at_us: 20,
            },
            stop_pkt,
            &mut links,
            &mut client_cb,
        )
        .unwrap();
    assert_eq!(
        client_cb.closed_streams,
        vec![(assoc, s0, StreamCloseReason::PeerStopSending { error_code: 0x99 })]
    );
    assert_eq!(links.aborted_streams, vec![(assoc, s0)]);
    // Client automatically emitted `RESET_STREAM(final_size = 5)` in response to `STOP_SENDING`!
    let (_, auto_rst) = links.link0_sent.pop_front().unwrap();
    let (decoded_rst, _) = decode_frame(auto_rst.bytes(), 0).unwrap();
    assert_eq!(
        decoded_rst,
        Frame::ResetStream {
            stream_id: s0,
            error_code: 0x99,
            final_size: 5,
        }
    );
    drop(auto_rst);
    assert!(matches!(
        client.write_stream(assoc, s0, TxStreamData::Bytes(b"more"), false, &mut links),
        Err(MuxSendError::Error {
            error: MuxError::StreamReset,
            ..
        })
    ));

    // 2. Repeated out-of-order stream resets reclaim unconsumed bytes to association `MAX_DATA`
    // AND `RESET_STREAM.final_size` violations are rejected!
    for round in 0..6u64 {
        let sid = StreamId((round + 1) * 4); // client bidi streams 4, 8, 12, 16, 20, 24
        // Send out-of-order offset 4..16 (12 bytes unconsumed in RX buffer!)
        let mut ooo = pool.alloc().unwrap();
        let mut h = [0u8; 32];
        let hn = encode_stream_header(sid, 4, 12, false, true, &mut h).unwrap();
        ooo.append(&h[..hn]).unwrap();
        ooo.append(b"0123456789ab").unwrap();
        server
            .receive_packet(
                RxMeta {
                    association: assoc,
                    received_at_us: 100 + round,
                },
                ooo,
                &mut links,
                &mut server_cb,
            )
            .unwrap();

        if round == 0 {
            // `final_size < highest_received` (8 < 16) MUST fail with `FlowControlViolation`!
            let mut bad_rst = pool.alloc().unwrap();
            let mut rb = [0u8; 32];
            let rn = encode_control_frame(
                &Frame::ResetStream {
                    stream_id: sid,
                    error_code: 1,
                    final_size: 8,
                },
                &mut rb,
            )
            .unwrap();
            bad_rst.append(&rb[..rn]).unwrap();
            assert_eq!(
                server.receive_packet(
                    RxMeta {
                        association: assoc,
                        received_at_us: 150
                    },
                    bad_rst,
                    &mut links,
                    &mut server_cb
                ),
                Err(MuxError::FlowControlViolation)
            );
        }

        // Valid `RESET_STREAM(final_size = 16)` charges 16 and immediately returns all 16 unconsumed bytes
        // to `server`'s association `MAX_DATA` window, so 6 x 16 = 96 bytes succeed over a 32-byte window!
        let mut ok_rst = pool.alloc().unwrap();
        let mut rb = [0u8; 32];
        let rn = encode_control_frame(
            &Frame::ResetStream {
                stream_id: sid,
                error_code: 2,
                final_size: 16,
            },
            &mut rb,
        )
        .unwrap();
        ok_rst.append(&rb[..rn]).unwrap();
        server
            .receive_packet(
                RxMeta {
                    association: assoc,
                    received_at_us: 200 + round,
                },
                ok_rst,
                &mut links,
                &mut server_cb,
            )
            .unwrap();

        // Deliver any `MAX_DATA` update emitted by `server` back to `client`
        while let Some((_, ctrl_pkt)) = links.link0_sent.pop_front() {
            let _ = client.receive_packet(
                RxMeta {
                    association: assoc,
                    received_at_us: 300 + round,
                },
                ctrl_pkt,
                &mut links,
                &mut client_cb,
            );
        }
    }
    assert_eq!(pool.available(), 16);
}

#[test]
fn pool_refcount_saturation_and_send_bounds() {
    fn assert_send<T: Send>() {}
    assert_send::<crate::StaticPacketLease<'static, 2>>();
    assert_send::<crate::HeapPacketLease<'static, 2>>();
    assert_send::<crate::XipLazyPacket>();

    static POOL: crate::StaticPacketPool<2> = crate::StaticPacketPool::new();
    assert_eq!(POOL.available(), 2);

    let mut base = (&POOL).alloc().unwrap();
    base.append(b"saturate-refcount").unwrap();
    assert_eq!(POOL.available(), 1);

    let mut clones = Vec::with_capacity(254);
    for _ in 0..254 {
        clones.push(base.try_clone().unwrap());
    }
    // Total live references == 255 (`u8::MAX`). A 256th clone MUST return `Err(PoolError::Exhausted)`
    // without wrapping `AtomicU8` to 0!
    assert_eq!(base.try_clone().unwrap_err(), crate::PoolError::Exhausted);
    assert!(!base.is_unique());
    assert_eq!(
        base.append(b"!"),
        Err(crate::PoolError::Shared),
        "lease must remain shared (refs == 255), never wrapped to unique"
    );

    drop(clones);
    assert!(base.is_unique());
    assert_eq!(POOL.available(), 1);
    drop(base);
    assert_eq!(POOL.available(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tokio_mux_unidirectional_streams_and_read_drop_stop_sending() {
    use crate::TokioMux;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let (c_sock, s_sock) = UnixStream::pair().unwrap();
    let (client_mux, _client_acceptor) = TokioMux::client(c_sock, crate::TokioMuxConfig::default());
    let (_server_mux, mut server_acceptor) =
        TokioMux::server(s_sock, crate::TokioMuxConfig::default());

    // 1. Outbound unidirectional stream (`open_uni`): reading locally returns immediate EOF,
    // writing on the accepted peer-uni stream fails immediately with `BrokenPipe`.
    let mut c_uni = client_mux.open_uni().await.unwrap();
    assert!(c_uni.stream_id().is_uni());
    let mut empty_check = [0u8; 8];
    assert_eq!(c_uni.read(&mut empty_check).await.unwrap(), 0);
    c_uni.write_all(b"one-way-message").await.unwrap();
    c_uni.finish().await.unwrap();

    let mut s_uni = server_acceptor.accept().await.unwrap();
    assert!(s_uni.stream_id().is_uni());
    assert_eq!(
        s_uni.write(b"illegal-reply").await.unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
    let mut got = Vec::new();
    s_uni.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"one-way-message");
    drop(c_uni);
    drop(s_uni);

    // 2. Dropping `MuxReadHalf` early on a bidirectional stream sends `STOP_SENDING`,
    // waking/failing peer writes with `BrokenPipe` while local `MuxWriteHalf` keeps working!
    let mut c_bidi = client_mux.open_bidi().await.unwrap();
    c_bidi.write_all(b"init").await.unwrap();
    c_bidi.flush().await.unwrap();

    let s_bidi = server_acceptor.accept().await.unwrap();
    let (s_read, mut s_write) = s_bidi.into_split();
    // Server drops `s_read` immediately -> emits `STOP_SENDING` to client!
    drop(s_read);

    // Wait briefly for `STOP_SENDING` control packet to arrive at client, then verify client writes fail with `BrokenPipe`
    let mut saw_broken_pipe = false;
    for _ in 0..50 {
        match c_bidi.write(b"more-after-stop").await {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                saw_broken_pipe = true;
                break;
            }
            Ok(_) => tokio::time::sleep(std::time::Duration::from_millis(2)).await,
            Err(other) => panic!("unexpected write error: {other:?}"),
        }
    }
    assert!(
        saw_broken_pipe,
        "dropping MuxReadHalf must send STOP_SENDING and fail peer writer with BrokenPipe"
    );

    // Meanwhile `s_write` (the server's write half of that same bidi stream) can still send to `c_bidi`'s read half!
    s_write.write_all(b"server-half-still-open").await.unwrap();
    s_write.finish().await.unwrap();

    let mut client_rx = Vec::new();
    c_bidi.read_to_end(&mut client_rx).await.unwrap();
    assert_eq!(client_rx, b"server-half-still-open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tokio_mux_packet_link_mixed_mtu_multipath_and_multi_assoc_host() {
    use crate::{AssociationId, OWNER_ASSOC, StreamPriority, TokioMux, TokioMuxConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    // 1. Owner association (`OWNER_ASSOC = AssociationId(1)`) bonded across both a stream link
    // (`cost = 10`, default 1532 MTU) and a PPP-like packet link (`cost = 20`, 700-byte MTU).
    let (c_sock, s_sock) = UnixStream::pair().unwrap();
    let (c_pkt_tx, s_pkt_rx) = tokio::sync::mpsc::channel(32);
    let (s_pkt_tx, c_pkt_rx) = tokio::sync::mpsc::channel(32);

    let (client_mux, _client_acceptor) = TokioMux::spawn(true, TokioMuxConfig::default());
    let (server_mux, mut server_acceptor) = TokioMux::spawn(false, TokioMuxConfig::default());

    client_mux.add_stream_link_on(OWNER_ASSOC, c_sock, 10, 4);
    client_mux.add_packet_link_on(OWNER_ASSOC, c_pkt_tx, c_pkt_rx, 700, 20, 16);

    server_mux.add_uds_stream_link(s_sock, 10);
    server_mux.add_packet_link(s_pkt_tx, s_pkt_rx, 700, 20);

    // 2. Host-side second association (`AssociationId(2)`) on its own dedicated stream link.
    let assoc2 = AssociationId(2);
    let (c_sock2, s_sock2) = UnixStream::pair().unwrap();
    let (client2_mux, _client2_acceptor) = TokioMux::spawn(true, TokioMuxConfig::default());
    client2_mux.set_default_association(assoc2, true).unwrap();
    client2_mux.add_stream_link_on(assoc2, c_sock2, 10, 8);
    server_mux.add_association(assoc2, false).unwrap();
    server_mux.add_stream_link_on(assoc2, s_sock2, 10, 8);

    let server_task = tokio::spawn(async move {
        for _ in 0..2 {
            let mut s = server_acceptor.accept().await.unwrap();
            let mut req = Vec::new();
            s.read_to_end(&mut req).await.unwrap();
            s.write_all(&req).await.unwrap();
            s.finish().await.unwrap();
        }
    });

    let mut c1 = client_mux
        .open_stream_on(OWNER_ASSOC, true, StreamPriority::NORMAL)
        .await
        .unwrap();
    assert_eq!(c1.association_id(), OWNER_ASSOC);
    let payload: Vec<u8> = (0..12_000).map(|i| (i % 251) as u8).collect();
    c1.write_all(&payload).await.unwrap();
    c1.finish().await.unwrap();

    let mut resp1 = Vec::new();
    c1.read_to_end(&mut resp1).await.unwrap();
    assert_eq!(resp1, payload);

    let mut c2 = client2_mux.open_bidi().await.unwrap();
    assert_eq!(c2.association_id(), assoc2);
    c2.write_all(b"second-association-over-dedicated-stream")
        .await
        .unwrap();
    c2.finish().await.unwrap();
    let mut resp2 = Vec::new();
    c2.read_to_end(&mut resp2).await.unwrap();
    assert_eq!(resp2, b"second-association-over-dedicated-stream");

    server_task.await.unwrap();
}


