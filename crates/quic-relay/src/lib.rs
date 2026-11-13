//! Multi-hop QUIC DCID routing, zero-copy packet rewriting, `PATH_OPEN` / `PATH_OPEN_ACK`
//! setup codecs, and ESP-XIP runtime relay table (`xip_quic.c` / `xip-runtime-host` compatible).
//!
//! `quic-relay` is `#![no_std]` (requiring `alloc`) and builds directly on [`quic_base`]:
//! - [`router`]: Capacity-limited [`DcidRegistry`], [`PacketRouter`], `PATH_OPEN` / `PATH_OPEN_ACK`
//!   setup codecs ([`SetupRequest`], [`SetupReply`], [`SetupTransactionTable`]), and zero-copy
//!   in-place DCID rewriting ([`rewrite_dcid_in_place`], [`dispatch_pool_packet`]).
//! - [`xip`]: 100% ABI- and behavior-compatible implementation of the ESP-XIP C runtime relay
//!   (`xip_quic.h` / `xip_quic.c`) and Rust host runtime (`xip-runtime-host`), including
//!   [`XipRelayTable`](xip::XipRelayTable), [`ReplyTable`](xip::ReplyTable), weighted round-robin
//!   hop selection, high-range `(1 << 60) | n` relay CID allocation, and outer circuit-header
//!   prepend/strip helpers.

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

pub mod router;
pub mod xip;

pub use quic_base::{
    ConnectionId, DEFAULT_HEADROOM, DEFAULT_MAX_PAYLOAD, DEFAULT_SLOT_SIZE, DEFAULT_TAIL,
    PacketPool, PoolError, PoolPacket, ShortHeader, ShortHeaderPrefix, SlabPacket, SlabPool,
    StaticPacketLease, StaticPacketPool, XipLazyPacket, XipLazyPool,
};

pub use router::{
    DEFAULT_MAX_CACHED_SETUP_REPLIES, DEFAULT_MAX_PACKET_SIZE, DEFAULT_MAX_PENDING_SETUPS,
    DEFAULT_SETUP_LEASE_US, DEFAULT_SETUP_PENDING_TIMEOUT_US, DEFAULT_SETUP_REPLY_BYTES,
    DEFAULT_SETUP_REPLY_RETENTION_US, DEFAULT_SETUP_REPLY_STORAGE_BYTES, DMESH_LONG_HEADER_VERSION,
    DcidIngress, DcidPacket, DcidPacketError, DcidPoolPacket, DcidRegistry, DcidRegistryError,
    DcidTarget, ForwardDestination, ForwardNextHop, ForwardRule, LONG_PACKET_INITIAL,
    LONG_PACKET_PATH_OPEN, LONG_PACKET_PATH_OPEN_ACK, LongHeader, MAX_NEARBY_RETURN_RELAYS,
    MAX_SETUP_BLOCK_BYTES, MAX_SETUP_BLOCKS, MAX_SETUP_BOOTSTRAP_ACK_BYTES, MAX_SETUP_BODY_BYTES,
    MAX_SETUP_HOP_ADDRESS_BYTES, NearbyRelayHint, NearbyRelayHints, PacketRouter, RelayError,
    RelayRouteMode, Role, RouterConfig, SETUP_BLOCK_ENDPOINT, SETUP_BLOCK_RELAY,
    SETUP_REQUEST_VERSION, SETUP_VERSION, SetupBlock, SetupBlockBytes, SetupBootstrapAck,
    SetupCircuitKey, SetupCreateEndpoint, SetupDownstreamReply, SetupHopInstruction,
    SetupJoinEndpoint, SetupMode, SetupRelayCids, SetupRelayState, SetupReply, SetupRequest,
    SetupRequestView, SetupResult, SetupTransactionError, SetupTransactionLookup,
    SetupTransactionTable, decode_long_packet, decode_routing_prefix, decode_setup_reply_packet,
    decode_setup_request_packet, dispatch_packet, dispatch_pool_packet, encode_long_packet,
    rewrite_bootstrap_destination, rewrite_dcid, rewrite_dcid_in_place,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xip::{
        CID_MAX, ERR_ARG, ERR_BUSY, ERR_NOMEM, ERR_NOTFOUND, QuicClass, QuicKind, RelayHop,
        RelayRoute, ReplyTable, TABLE_MAX, VERSION_CBOR, VERSION_DMESH, XipRelayTable, classify,
        long_build, prepend_circuit_header, short_rewrite_packet, strip_circuit_header,
    };
    use alloc::vec;
    use alloc::vec::Vec;

    const FLAG_FIXED_BIT: u8 = 0x40;

    #[test]
    fn create_endpoint_hints_round_trip_and_keep_legacy_payloads() {
        let return_hints = NearbyRelayHints::new(&[
            NearbyRelayHint {
                relay_id: [1; 8],
                hop: SetupHopInstruction::new(2, &[3, 4], 60_000_000, 1024).unwrap(),
            },
            NearbyRelayHint {
                relay_id: [5; 8],
                hop: SetupHopInstruction::new(3, &[6], 30_000_000, 512).unwrap(),
            },
        ])
        .unwrap();
        let endpoint = SetupCreateEndpoint {
            initial_packet: &[0x91, 0x92, 0x93],
            return_hints,
        };
        let mut encoded = [0u8; MAX_SETUP_BLOCK_BYTES];
        let used = endpoint.encode(&mut encoded).unwrap();
        let (initial_packet, decoded_hints) =
            SetupCreateEndpoint::decode(&encoded[..used], 2).unwrap();
        assert_eq!(initial_packet, endpoint.initial_packet);
        assert_eq!(decoded_hints, return_hints);

        let (legacy_initial, legacy_hints) =
            SetupCreateEndpoint::decode(endpoint.initial_packet, 1).unwrap();
        assert_eq!(legacy_initial, endpoint.initial_packet);
        assert_eq!(legacy_hints, NearbyRelayHints::EMPTY);
    }

    #[test]
    fn endpoint_and_forward_target_share_one_registry() {
        let endpoint = ConnectionId::new(4).unwrap();
        let relay = ConnectionId::new(0x234).unwrap();
        let mut registry = DcidRegistry::<u8, u16>::new();
        registry.set_max_entries(2);
        registry.insert_endpoint(endpoint, 7).unwrap();
        registry
            .install_forward(
                relay,
                ForwardRule {
                    next_hop: 9,
                    destination: ForwardDestination::Bootstrap,
                    lease_duration_us: 1_000,
                    lease_expires_at_us: 10_000,
                    lease_group_id: 0,
                    packet_quota: 0,
                    forwarded_packets: 0,
                    forwarded_control_packets: 0,
                    quota_window_started_us: 0,
                },
            )
            .unwrap();

        let mut endpoint_packet = [0; 16];
        let endpoint_len = ShortHeader {
            flags: FLAG_FIXED_BIT,
            dcid: endpoint,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut endpoint_packet)
        .unwrap();
        let endpoint_prefix = ShortHeader::decode_prefix(&endpoint_packet[..endpoint_len]).unwrap();
        assert!(matches!(
            registry.ingress(endpoint_prefix),
            Ok(DcidIngress::Endpoint(_, 7))
        ));

        let mut relay_packet = [0; 16];
        let relay_len = ShortHeader {
            flags: FLAG_FIXED_BIT,
            dcid: relay,
            packet_number: 2,
            packet_number_len: 1,
        }
        .encode(&mut relay_packet)
        .unwrap();
        let relay_prefix = ShortHeader::decode_prefix(&relay_packet[..relay_len]).unwrap();
        assert!(matches!(
            registry.ingress(relay_prefix),
            Ok(DcidIngress::Forward(_, ForwardRule { next_hop: 9, .. }))
        ));
    }

    #[test]
    fn directional_forward_rules_install_atomically_and_share_one_lease() {
        let first = ConnectionId::new(0x31).unwrap();
        let second = ConnectionId::new(0x32).unwrap();
        let mut router = PacketRouter::<(), u16>::new();
        router.set_max_entries(2);
        let make_rule = |next_hop, destination| ForwardRule {
            next_hop,
            destination: ForwardDestination::Connection(destination),
            lease_duration_us: 1_000,
            lease_expires_at_us: 100,
            lease_group_id: 42,
            packet_quota: 0,
            forwarded_packets: 0,
            forwarded_control_packets: 0,
            quota_window_started_us: 0,
        };
        router
            .register_forward_pair(
                first,
                make_rule(1, ConnectionId::new(0x41).unwrap()),
                second,
                make_rule(2, ConnectionId::new(0x42).unwrap()),
            )
            .unwrap();
        assert_eq!(router.route_count(), 2);
        assert_eq!(router.next_forward_lease_deadline(), Some(100));

        let mut packet = [0u8; 16];
        let used = ShortHeader {
            flags: FLAG_FIXED_BIT,
            dcid: first,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        assert!(router.refresh_forward_lease(&packet[..used], 99).unwrap());
        assert_eq!(router.next_forward_lease_deadline(), Some(1_099));
        assert_eq!(router.expire_forward_leases(1_098), 0);
        assert_eq!(router.expire_forward_leases(1_099), 2);
        assert_eq!(router.route_count(), 0);
    }

    #[test]
    fn forward_packet_quota_reserves_control_capacity() {
        let mut router = PacketRouter::<(), u16>::new();
        router.set_max_entries(2);
        let first = ConnectionId::new(0x51).unwrap();
        let second = ConnectionId::new(0x52).unwrap();
        let make_rule = |next_hop, destination| ForwardRule {
            next_hop,
            destination: ForwardDestination::Connection(destination),
            lease_duration_us: 1_000,
            lease_expires_at_us: 1_000,
            lease_group_id: 91,
            packet_quota: 4,
            forwarded_packets: 0,
            forwarded_control_packets: 0,
            quota_window_started_us: 0,
        };
        router
            .register_forward_pair(
                first,
                make_rule(1, ConnectionId::new(0x61).unwrap()),
                second,
                make_rule(2, ConnectionId::new(0x62).unwrap()),
            )
            .unwrap();

        assert!(router.consume_forward_quota(first, false, 0));
        assert!(router.consume_forward_quota(first, false, 0));
        assert!(router.consume_forward_quota(first, false, 0));
        assert!(!router.consume_forward_quota(first, false, 0));
        assert!(router.consume_forward_quota(first, true, 0));
        assert!(!router.consume_forward_quota(first, true, 0));
        assert!(router.consume_forward_quota(second, false, 0));
        assert!(router.consume_forward_quota(first, false, 1_000));
    }

    #[test]
    fn failed_directional_forward_install_leaves_registry_unchanged() {
        let first = ConnectionId::new(0x31).unwrap();
        let second = ConnectionId::new(0x32).unwrap();
        let mut registry = DcidRegistry::<(), u16>::new();
        registry.set_max_entries(1);
        let rule = |next_hop, destination| ForwardRule {
            next_hop,
            destination: ForwardDestination::Connection(destination),
            lease_duration_us: 1_000,
            lease_expires_at_us: 2_000,
            lease_group_id: 7,
            packet_quota: 0,
            forwarded_packets: 0,
            forwarded_control_packets: 0,
            quota_window_started_us: 0,
        };
        assert_eq!(
            registry.install_forward_pair(
                first,
                rule(1, ConnectionId::new(0x41).unwrap()),
                second,
                rule(2, ConnectionId::new(0x42).unwrap()),
            ),
            Err(DcidRegistryError::Full)
        );
        assert_eq!(registry.len(), 0);

        registry.set_max_entries(3);
        registry.insert_endpoint(second, ()).unwrap();
        assert_eq!(
            registry.install_forward_pair(
                first,
                rule(1, ConnectionId::new(0x41).unwrap()),
                second,
                rule(2, ConnectionId::new(0x43).unwrap()),
            ),
            Err(DcidRegistryError::Occupied)
        );
        assert_eq!(registry.len(), 1);
        assert!(!registry.contains(first));
    }

    #[test]
    fn setup_transactions_deduplicate_replay_and_reject_conflicting_retries() {
        let source = ForwardNextHop {
            bearer: 1,
            peer_l2_address: 9,
        };
        let mut table = SetupTransactionTable::new(2, 4, 32, 16, 32, 10);
        assert!(matches!(
            table.begin(source, 7, b"setup", 8, 0, 100),
            SetupTransactionLookup::New
        ));
        assert!(matches!(
            table.begin(source, 7, b"setup", 8, 50, 500),
            SetupTransactionLookup::PendingRetry
        ));
        assert!(matches!(
            table.begin(source, 7, b"different", 8, 50, 500),
            SetupTransactionLookup::Conflict
        ));
        table.complete(source, 7, b"reply", 99).unwrap();
        assert_eq!(table.pending_count(), 0);
        assert_eq!(table.cached_count(), 1);
        assert!(matches!(
            table.begin(source, 7, b"setup", 8, 108, 500),
            SetupTransactionLookup::Replay(b"reply")
        ));
        assert_eq!(table.expire(109), 1);
        assert_eq!(table.cached_count(), 0);
        assert_eq!(table.reserved_reply_bytes(), 0);
    }

    #[test]
    fn setup_transaction_admission_reserves_reply_space_and_cancellation_releases_it() {
        let source = ForwardNextHop {
            bearer: 1,
            peer_l2_address: 9,
        };
        let mut table = SetupTransactionTable::new(1, 2, 32, 16, 8, 10);
        assert!(matches!(
            table.begin(source, 1, b"setup", 9, 0, 100),
            SetupTransactionLookup::Full
        ));
        assert!(matches!(
            table.begin(source, 1, b"setup", 8, 0, 100),
            SetupTransactionLookup::New
        ));
        assert!(matches!(
            table.begin(source, 2, b"other", 1, 1, 100),
            SetupTransactionLookup::Full
        ));
        assert!(table.cancel(source, 1));
        assert_eq!(table.pending_count(), 0);
        assert_eq!(table.reserved_reply_bytes(), 0);
        assert!(matches!(
            table.begin(source, 1, b"setup", 1, 1, 100),
            SetupTransactionLookup::Expired
        ));
        assert!(matches!(
            table.begin(source, 2, b"other", 1, 1, 100),
            SetupTransactionLookup::New
        ));
        assert_eq!(table.expire(100), 1);
        assert_eq!(table.pending_count(), 0);
    }

    #[test]
    fn idle_pending_setup_expiry_releases_reservation_and_retained_entry() {
        let source = ForwardNextHop {
            bearer: 1,
            peer_l2_address: 9,
        };
        let mut table = SetupTransactionTable::new(1, 2, 32, 16, 32, 10);
        assert!(matches!(
            table.begin(source, 4, b"setup", 8, 0, 100),
            SetupTransactionLookup::New
        ));
        assert_eq!(table.pending_count(), 1);
        assert_eq!(table.reserved_reply_bytes(), 8);
        assert_eq!(table.next_deadline(), Some(100));

        assert_eq!(table.expire(100), 1);
        assert_eq!(table.pending_count(), 0);
        assert_eq!(table.cached_count(), 0);
        assert_eq!(table.reserved_reply_bytes(), 0);
        assert_eq!(table.next_deadline(), Some(110));
        assert!(matches!(
            table.begin(source, 4, b"setup", 8, 100, 200),
            SetupTransactionLookup::Expired
        ));

        assert_eq!(table.expire(110), 1);
        assert_eq!(table.next_deadline(), None);
        assert_eq!(table.reserved_reply_bytes(), 0);
    }

    #[test]
    fn setup_request_codec_preserves_versioned_length_delimited_blocks() {
        let blocks = [
            SetupBlock {
                kind: 1,
                version: 1,
                protection: 0,
                payload: b"relay egress",
            },
            SetupBlock {
                kind: 2,
                version: 3,
                protection: 0,
                payload: b"endpoint join settings",
            },
        ];
        let request = SetupRequest {
            transaction_id: 17,
            mode: SetupMode::Join,
            route_mode: RelayRouteMode::Layered,
            circuit: SetupCircuitKey {
                opener_role: Role::Server,
                sequence: 9,
            },
            destination_vip: Some(0x1020_3040_5060_7080),
            previous_reverse_cid: None,
            blocks: &blocks,
        };
        let mut encoded = [0u8; 256];
        let used = request.encode(&mut encoded).unwrap();
        let block_offset = {
            let decoded = SetupRequest::decode(&encoded[..used]).unwrap();
            assert_eq!(decoded.transaction_id, request.transaction_id);
            assert_eq!(decoded.mode, request.mode);
            assert_eq!(decoded.circuit, request.circuit);
            assert_eq!(decoded.destination_vip, request.destination_vip);
            assert_eq!(decoded.blocks.count(), 2);
            assert_eq!(decoded.blocks.get(0).unwrap().unwrap(), blocks[0]);
            assert_eq!(decoded.blocks.get(1).unwrap().unwrap(), blocks[1]);
            assert!(decoded.blocks.get(2).is_none());
            used - decoded.blocks.as_bytes().len()
        };

        assert_eq!(
            SetupRequest::decode(&encoded[..used - 1]),
            Err(RelayError::Invalid)
        );
        encoded[used] = 0;
        assert_eq!(
            SetupRequest::decode(&encoded[..used + 1]),
            Err(RelayError::Invalid)
        );

        encoded[block_offset + 2] = 1;
        assert_eq!(
            SetupRequest::decode(&encoded[..used]),
            Err(RelayError::Invalid)
        );
    }

    #[test]
    fn setup_packets_use_distinct_connectionless_long_header_types() {
        let payload = [0x11, 0x22];
        let block = SetupBlock {
            kind: SETUP_BLOCK_ENDPOINT,
            version: 1,
            protection: 0,
            payload: &payload,
        };
        let request = SetupRequest {
            transaction_id: 11,
            mode: SetupMode::Create,
            route_mode: RelayRouteMode::Layered,
            circuit: SetupCircuitKey {
                opener_role: Role::Client,
                sequence: 3,
            },
            destination_vip: Some(0x0102_0304_0506_0708),
            previous_reverse_cid: None,
            blocks: core::slice::from_ref(&block),
        };
        let mut packet = [0u8; DEFAULT_MAX_PACKET_SIZE];
        let used = request.encode_packet(&mut packet).unwrap();
        let decoded = decode_setup_request_packet(&packet[..used]).unwrap();
        assert_eq!(decoded.transaction_id, request.transaction_id);
        assert_eq!(decoded.mode, request.mode);
        assert_eq!(decoded.circuit, request.circuit);
        assert_eq!(decoded.destination_vip, request.destination_vip);
        assert_eq!(decoded.blocks.get(0).unwrap().unwrap(), block);

        let reply = SetupReply {
            transaction_id: request.transaction_id,
            circuit: request.circuit,
            result: SetupResult::Rejected { code: 9 },
            bootstrap_ack: None,
            relay_cids: SetupRelayCids::empty(),
        };
        let used = reply.encode_packet(&mut packet).unwrap();
        assert_eq!(decode_setup_reply_packet(&packet[..used]), Ok(reply));
        assert_eq!(
            decode_setup_request_packet(&packet[..used]),
            Err(RelayError::Invalid)
        );
    }

    #[test]
    fn setup_request_codec_rejects_invalid_keys_and_excess_blocks() {
        let payload = [1u8];
        let block = SetupBlock {
            kind: 1,
            version: 1,
            protection: 0,
            payload: &payload,
        };
        let mut output = [0u8; 128];
        let mut request = SetupRequest {
            transaction_id: 0,
            mode: SetupMode::Create,
            route_mode: RelayRouteMode::Layered,
            circuit: SetupCircuitKey {
                opener_role: Role::Client,
                sequence: 1,
            },
            destination_vip: None,
            previous_reverse_cid: None,
            blocks: core::slice::from_ref(&block),
        };
        assert_eq!(request.encode(&mut output), Err(RelayError::Invalid));
        request.transaction_id = 1;
        request.circuit.sequence = 0;
        assert_eq!(request.encode(&mut output), Err(RelayError::Invalid));

        request.circuit.sequence = 1;
        let too_many = [block; MAX_SETUP_BLOCKS + 1];
        request.blocks = &too_many;
        assert_eq!(request.encode(&mut output), Err(RelayError::Invalid));
    }

    #[test]
    fn setup_hop_instruction_round_trips_and_checks_egress_limits() {
        let instruction = SetupHopInstruction {
            address_kind: 3,
            address_len: 6,
            address: [1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            lease_us: 30_000_000,
            packet_quota: 4096,
        };
        let mut encoded = [0u8; MAX_SETUP_BLOCK_BYTES];
        let used = instruction.encode(&mut encoded).unwrap();
        assert_eq!(
            SetupHopInstruction::decode(&encoded[..used]),
            Ok(instruction)
        );
        assert_eq!(
            SetupHopInstruction::decode(&encoded[..used - 1]),
            Err(RelayError::Truncated)
        );

        let invalid = SetupHopInstruction {
            address_kind: 0,
            ..instruction
        };
        assert_eq!(invalid.encode(&mut encoded), Err(RelayError::Invalid));
    }

    #[test]
    fn layered_setup_consumes_only_the_current_hop_block() {
        let instruction = SetupHopInstruction {
            address_kind: 3,
            address_len: 6,
            address: [1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            lease_us: 30_000_000,
            packet_quota: 4096,
        };
        let mut relay_payload = [0u8; MAX_SETUP_BLOCK_BYTES];
        let relay_payload_len = instruction.encode(&mut relay_payload).unwrap();
        let endpoint_payload = [0xaa, 0xbb, 0xcc];
        let blocks = [
            SetupBlock {
                kind: SETUP_BLOCK_RELAY,
                version: 1,
                protection: 0,
                payload: &relay_payload[..relay_payload_len],
            },
            SetupBlock {
                kind: SETUP_BLOCK_ENDPOINT,
                version: 2,
                protection: 0,
                payload: &endpoint_payload,
            },
        ];
        let request = SetupRequest {
            transaction_id: 19,
            mode: SetupMode::Create,
            route_mode: RelayRouteMode::Layered,
            circuit: SetupCircuitKey {
                opener_role: Role::Client,
                sequence: 7,
            },
            destination_vip: Some(0x0102_0304_0506_0708),
            previous_reverse_cid: None,
            blocks: &blocks,
        };
        let mut encoded = [0u8; 256];
        let used = request.encode(&mut encoded).unwrap();
        let decoded = SetupRequest::decode(&encoded[..used]).unwrap();
        assert_eq!(decoded.current_hop_instruction().unwrap().address_kind, 3);

        let mut forwarded = [0u8; 256];
        let forwarded_len = decoded.encode_after_first_block(&mut forwarded).unwrap();
        let forwarded = SetupRequest::decode(&forwarded[..forwarded_len]).unwrap();
        assert_eq!(forwarded.transaction_id, request.transaction_id);
        assert_eq!(forwarded.circuit, request.circuit);
        assert_eq!(forwarded.destination_vip, request.destination_vip);
        assert_eq!(forwarded.blocks.count(), 1);
        assert_eq!(forwarded.blocks.get(0).unwrap().unwrap(), blocks[1]);
        assert_eq!(
            forwarded.current_hop_instruction(),
            Err(RelayError::Invalid)
        );
        assert_eq!(
            decoded.encode_after_first_block(&mut [0u8; 1]),
            Err(RelayError::BufferTooSmall)
        );
    }

    #[test]
    fn setup_reply_codec_echoes_transaction_key_and_result() {
        let accepted = SetupReply {
            transaction_id: 23,
            circuit: SetupCircuitKey {
                opener_role: Role::Client,
                sequence: 5,
            },
            result: SetupResult::Accepted {
                endpoint_cid: ConnectionId::new(0x1234).unwrap(),
                lease_us: 30_000_000,
            },
            bootstrap_ack: None,
            relay_cids: SetupRelayCids::empty(),
        };
        let rejected = SetupReply {
            result: SetupResult::Rejected { code: 4 },
            ..accepted
        };
        let mut output = [0u8; 64];
        let used = accepted.encode(&mut output).unwrap();
        assert_eq!(SetupReply::decode(&output[..used]), Ok(accepted));
        let used = rejected.encode(&mut output).unwrap();
        assert_eq!(SetupReply::decode(&output[..used]), Ok(rejected));
        output[used] = 0;
        assert_eq!(
            SetupReply::decode(&output[..used + 1]),
            Err(RelayError::Invalid)
        );
    }

    #[test]
    fn dispatches_endpoint_and_forward_once_and_in_place() {
        let endpoint = ConnectionId::new(4).unwrap();
        let relay = ConnectionId::new(0x234).unwrap();
        let mut registry = DcidRegistry::<u8, u16>::new();
        registry.set_max_entries(2);
        registry.insert_endpoint(endpoint, 7).unwrap();
        registry
            .install_forward(
                relay,
                ForwardRule {
                    next_hop: 9,
                    destination: ForwardDestination::Connection(ConnectionId::new(5).unwrap()),
                    lease_duration_us: 1_000,
                    lease_expires_at_us: 10_000,
                    lease_group_id: 0,
                    packet_quota: 0,
                    forwarded_packets: 0,
                    forwarded_control_packets: 0,
                    quota_window_started_us: 0,
                },
            )
            .unwrap();

        let mut output = [0; 32];
        let mut endpoint_packet = [0; 16];
        let endpoint_len = ShortHeader {
            flags: FLAG_FIXED_BIT,
            dcid: endpoint,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut endpoint_packet)
        .unwrap();
        assert!(matches!(
            dispatch_packet(&registry, &endpoint_packet[..endpoint_len], &mut output),
            Ok(DcidPacket::Endpoint { received_dcid, endpoint: 7 })
                if received_dcid == endpoint
        ));

        let mut relay_packet = [0; 16];
        let relay_len = ShortHeader {
            flags: FLAG_FIXED_BIT,
            dcid: relay,
            packet_number: 2,
            packet_number_len: 1,
        }
        .encode(&mut relay_packet)
        .unwrap();
        let used =
            match dispatch_packet(&registry, &relay_packet[..relay_len], &mut output).unwrap() {
                DcidPacket::Forward { rule, used, .. } => {
                    assert_eq!(rule.next_hop, 9);
                    used
                }
                _ => panic!("expected forward"),
            };
        let (rewritten, _) = ShortHeader::decode(&output[..used]).unwrap();
        assert_eq!(rewritten.dcid.value(), 5);
        assert_eq!(rewritten.packet_number, 2);

        // Also test zero-copy in-place PoolPacket dispatch (2-byte DCID 0x234 -> 1-byte DCID 5)
        let pool: StaticPacketPool<4, 256> = StaticPacketPool::new();
        let mut pkt = (&pool).alloc().unwrap();
        pkt.append(&relay_packet[..relay_len]).unwrap();
        pkt.append(b"payload").unwrap();
        let pkt = match dispatch_pool_packet(&registry, pkt, 0, 256).unwrap() {
            DcidPoolPacket::Forward {
                received_dcid,
                rule,
                packet,
            } => {
                assert_eq!(received_dcid, relay);
                assert_eq!(rule.next_hop, 9);
                packet
            }
            _ => panic!("expected pool forward"),
        };
        let (hdr, hdr_len) = ShortHeader::decode(pkt.bytes()).unwrap();
        assert_eq!(hdr.dcid.value(), 5);
        assert_eq!(hdr.packet_number, 2);
        assert_eq!(&pkt.bytes()[hdr_len..], b"payload");
    }

    #[test]
    fn bootstrap_forwarding_uses_an_empty_long_header_destination() {
        let relay = ConnectionId::new(0x234).unwrap();
        let source = ConnectionId::new(11).unwrap();
        let mut registry = DcidRegistry::<(), u16>::new();
        registry.set_max_entries(1);
        registry
            .install_forward(
                relay,
                ForwardRule {
                    next_hop: 9,
                    destination: ForwardDestination::Bootstrap,
                    lease_duration_us: 1_000,
                    lease_expires_at_us: 10_000,
                    lease_group_id: 0,
                    packet_quota: 0,
                    forwarded_packets: 0,
                    forwarded_control_packets: 0,
                    quota_window_started_us: 0,
                },
            )
            .unwrap();
        let mut packet = [0; 64];
        let packet_len = encode_long_packet(
            LONG_PACKET_INITIAL,
            Some(relay),
            Some(source),
            1,
            4,
            &[0xa0],
            &mut packet,
        )
        .unwrap();
        let mut output = [0; 64];
        let DcidPacket::Forward { used, .. } =
            dispatch_packet(&registry, &packet[..packet_len], &mut output).unwrap()
        else {
            panic!("bootstrap packet must be forwarded")
        };
        let (header, _, _) = decode_long_packet(&output[..used]).unwrap();
        assert_eq!(header.dcid, None);
        assert_eq!(header.scid, Some(source));
    }

    #[test]
    fn an_initial_with_an_empty_destination_is_not_a_registry_route() {
        let source = ConnectionId::new(11).unwrap();
        let registry = DcidRegistry::<(), u16>::new();
        let mut packet = [0; 64];
        let packet_len = encode_long_packet(
            LONG_PACKET_INITIAL,
            None,
            Some(source),
            1,
            4,
            &[0xa0],
            &mut packet,
        )
        .unwrap();
        let mut output = [0; 64];
        assert!(matches!(
            dispatch_packet(&registry, &packet[..packet_len], &mut output),
            Err(DcidPacketError::Registry(DcidRegistryError::Missing))
        ));
    }

    #[test]
    fn xip_classifier_and_relay_table_match_c_runtime_semantics() {
        const INITIAL: [u8; 15] = [
            0xc0, 0x44, 0x4d, 0x00, 0x01, 0x01, 0x2a, 0x02, 0x92, 0x34, 0x00, 0x03, 0x07, 0xaa,
            0xbb,
        ];
        const SHORT4: [u8; 9] = [0x41, 0xa0, 0x01, 0x23, 0x45, 0x00, 0x09, 0xde, 0xad];
        const DCID4: [u8; 4] = [0xa0, 0x01, 0x23, 0x45];

        let (c, h) = classify(&INITIAL, 0);
        assert_eq!(
            (
                c,
                h.is_long,
                h.version,
                h.dcid.as_slice(),
                h.scid.as_slice(),
                h.body
            ),
            (
                QuicClass::Long,
                true,
                VERSION_DMESH,
                &[0x2a][..],
                &[0x92, 0x34][..],
                10
            )
        );
        let (c, h) = classify(&SHORT4, 0);
        assert_eq!(
            (c, h.is_long, h.dcid.as_slice(), h.body),
            (QuicClass::Short, false, &DCID4[..], 5)
        );
        assert_eq!(classify(&[0x00, 1, 2, 3], 0).0, QuicClass::NotQuic);
        assert_eq!(
            classify(&[0x40, 0xe0, 1, 2, 3, 4, 5, 6, 7, 8], 0).0,
            QuicClass::Malformed
        );

        let mut table = XipRelayTable::new();
        for i in 1..=16u8 {
            assert_eq!(
                table.table_alloc(QuicKind::Local, 0, 0, &[]).unwrap(),
                vec![i]
            );
        }
        assert_eq!(table.table_remove(&[5]), 0);
        assert_eq!(
            table.table_alloc(QuicKind::Local, 0, 0, &[]).unwrap(),
            vec![5]
        );
        table.clear();

        // Weighted multi-hop route and owner isolation
        let mut r = RelayRoute {
            dcid: [0; CID_MAX],
            dcid_len: 1,
            hop_count: 2,
            endpoint: 0,
            reserved: 0,
            hops: [RelayHop::default(); 4],
        };
        r.dcid[0] = 2;
        r.hops[0] = RelayHop {
            link: 100,
            token: 11,
            weight: 1,
            cid_len: 1,
            rewritten_dcid: {
                let mut a = [0u8; CID_MAX];
                a[0] = 3;
                a
            },
            ..RelayHop::default()
        };
        r.hops[1] = RelayHop {
            token: 12,
            weight: 2,
            ..r.hops[0]
        };
        assert_eq!(table.relay_set(47, &r, 1), ERR_NOTFOUND);
        assert_eq!(table.relay_set(47, &r, 0), 0);
        assert_eq!(table.relay_set(49, &r, 1), ERR_BUSY);

        let mut count_11 = 0;
        let mut count_12 = 0;
        for _ in 0..30 {
            let selected = table.select(&[2], 1_000).unwrap();
            if selected.token == 11 {
                count_11 += 1;
            } else if selected.token == 12 {
                count_12 += 1;
            }
        }
        assert_eq!((count_11, count_12), (10, 20));

        // High-range relay_create with live reuse and expiry without recycling IDs
        let req = RelayRoute {
            dcid: [0; CID_MAX],
            dcid_len: 0,
            hop_count: 1,
            endpoint: 0,
            reserved: 0,
            hops: [
                r.hops[0],
                RelayHop::default(),
                RelayHop::default(),
                RelayHop::default(),
            ],
        };
        let mut first = req;
        assert_eq!(table.relay_create(47, &mut first, 100, true, 0), Ok(0));
        assert_eq!(first.dcid_len, 8);
        let mut reused = req;
        assert_eq!(table.relay_create(47, &mut reused, 100, true, 0), Ok(1));
        assert_eq!(reused.dcid, first.dcid);

        assert!(table.select(&first.dcid[..8], 70_000).is_some());
        let stats = table.relay_stats(47, &first.dcid[..8]).unwrap();
        assert_eq!(stats.last_used_us, 70_000);
        assert_eq!(table.relay_expire(Some(47), 140_000), 0);
        assert!(table.select(&first.dcid[..8], 171_000).is_none());
        assert_eq!(table.relay_expire(Some(47), 171_000), 1);

        let mut next = req;
        assert_eq!(table.relay_create(47, &mut next, 0, false, 171_000), Ok(0));
        assert_ne!(next.dcid, first.dcid);

        table.relay_release_owner(47);
        assert_eq!(table.len(), 0);
        assert_eq!(TABLE_MAX, 64);
        assert_eq!(ERR_ARG, -1);
        assert_eq!(ERR_NOMEM, -6);

        // ReplyTable correlation (swaps request's scid -> reply dcid, request's dcid -> reply scid)
        let mut replies = ReplyTable::new();
        let req_hdr = classify(&INITIAL, 0).1;
        replies.note(1, 5, 77, &req_hdr, 10);
        let note = replies.find(1, 5, 77, 5000).unwrap();
        assert_eq!(note.dcid, vec![0x92, 0x34]);
        assert_eq!(note.scid, vec![0x2a]);
        replies.done(1, 5, 77);
        assert!(replies.find(1, 5, 77, 5000).is_none());

        // Circuit header prepend/strip and short_rewrite_packet
        let pool = XipLazyPool::with_default_geometry(4);
        let mut pkt = pool.alloc().unwrap();
        let hdr_bytes = long_build(VERSION_CBOR, &[0x2a], &[0x2b]).unwrap();
        pkt.append(&hdr_bytes).unwrap();
        assert_eq!(prepend_circuit_header(&mut pkt, &[0x03], 0), Ok(()));
        assert_eq!(&pkt.bytes()[..3], &[0x40, 0x03, 0x00]);
        let outer_h = classify(pkt.bytes(), 0).1;
        assert_eq!(
            short_rewrite_packet(&mut pkt, &outer_h, &[0xa0, 1, 2, 3], 0),
            Ok(())
        );
        assert_eq!(&pkt.bytes()[..6], &[0x40, 0xa0, 1, 2, 3, 0x00]);
        let outer_h2 = classify(pkt.bytes(), 0).1;
        assert_eq!(
            strip_circuit_header(&mut pkt, &outer_h2),
            Ok(u64::from_le_bytes([0xa0, 1, 2, 3, 0, 0, 0, 0]))
        );
        assert_eq!(pkt.bytes(), hdr_bytes.as_slice());
    }

    #[test]
    fn zero_copy_pool_relay_forwards_between_two_single_stream_endpoints() {
        use quic_base::{RxOutcome, RxStreamChunk, TxStreamData};
        use quic_link::{
            LinkId, LinkProfile, SingleStreamCallbacks, SingleStreamConfig, SingleStreamEndpoint,
        };

        struct Collector {
            received: Vec<u8>,
            fin: bool,
        }
        impl SingleStreamCallbacks<XipLazyPacket> for Collector {
            fn on_stream_data(
                &mut self,
                chunk: RxStreamChunk<'_, XipLazyPacket>,
                fin: bool,
            ) -> RxOutcome<XipLazyPacket> {
                let n = chunk.len();
                self.received.extend_from_slice(chunk.bytes());
                if fin {
                    self.fin = true;
                }
                RxOutcome::Consumed(n)
            }
            fn on_datagram(&mut self, _packet: XipLazyPacket) {}
        }

        let pool = XipLazyPool::with_default_geometry(64);
        // Hop 1: client sends to relay_cid_ab (2B: 0x0234), relay rewrites in-place to server_cid (4B: 0x0001_2345).
        // Hop 2: server sends to relay_cid_ba (8B: (1<<60)|1), relay rewrites in-place to client_cid (1B: 0x2a).
        let client_cid = ConnectionId::new(0x2a).unwrap();
        let server_cid = ConnectionId::new(0x0001_2345).unwrap();
        let relay_cid_ab = ConnectionId::new(0x0234).unwrap();
        let relay_cid_ba = ConnectionId::new((1u64 << 60) | 1).unwrap();

        let mut client_cfg = SingleStreamConfig::default();
        client_cfg.assoc.local_cid = Some(client_cid);
        let mut server_cfg = SingleStreamConfig::default();
        server_cfg.assoc.local_cid = Some(server_cid);
        let mut client = SingleStreamEndpoint::new(pool.clone(), client_cfg);
        let mut server = SingleStreamEndpoint::new(pool.clone(), server_cfg);

        let link_id = LinkId(1);
        client
            .assoc_mut()
            .upsert_link(link_id, LinkProfile::udp_datagram(0, 1200, relay_cid_ab));
        server
            .assoc_mut()
            .upsert_link(link_id, LinkProfile::udp_datagram(0, 1200, relay_cid_ba));

        let mut relay_registry = DcidRegistry::<(), u8>::new();
        relay_registry
            .install_forward_pair(
                relay_cid_ab,
                ForwardRule {
                    next_hop: 1, // to server
                    destination: ForwardDestination::Connection(server_cid),
                    lease_duration_us: 60_000_000,
                    lease_expires_at_us: 60_000_000,
                    lease_group_id: 1,
                    packet_quota: 0,
                    forwarded_packets: 0,
                    forwarded_control_packets: 0,
                    quota_window_started_us: 0,
                },
                relay_cid_ba,
                ForwardRule {
                    next_hop: 2, // to client
                    destination: ForwardDestination::Connection(client_cid),
                    lease_duration_us: 60_000_000,
                    lease_expires_at_us: 60_000_000,
                    lease_group_id: 1,
                    packet_quota: 0,
                    forwarded_packets: 0,
                    forwarded_control_packets: 0,
                    quota_window_started_us: 0,
                },
            )
            .unwrap();

        let payload = b"end-to-end stream over zero-copy quic-relay!";
        let mut now_us = 1_000u64;
        assert_eq!(
            client
                .write_stream(TxStreamData::Bytes(payload), true, now_us)
                .unwrap(),
            payload.len()
        );

        let mut cb_client = Collector {
            received: Vec::new(),
            fin: false,
        };
        let mut cb_server = Collector {
            received: Vec::new(),
            fin: false,
        };

        for _ in 0..6 {
            client.poll_timers(now_us);
            server.poll_timers(now_us);

            while let Some(out) = client.assoc_mut().pop_outbound_packet() {
                client.assoc_mut().on_driver_complete(
                    out.link_id,
                    out.packet_number,
                    quic_link::LinkTxOutcome::Sent,
                    now_us,
                );
                // On a real network hop, the relay node receives the wire bytes into its own local
                // pool slot (refs == 1), while the sender retains its own SACK retransmit reference.
                let mut relay_pkt = pool.alloc().unwrap();
                relay_pkt.append(out.packet.bytes()).unwrap();
                drop(out.packet);
                match dispatch_pool_packet(&relay_registry, relay_pkt, 0, 1500).unwrap() {
                    DcidPoolPacket::Forward { rule, packet, .. } => {
                        assert_eq!(rule.next_hop, 1);
                        let (hdr, _) = ShortHeader::decode(packet.bytes()).unwrap();
                        assert_eq!(hdr.dcid, server_cid);
                        server
                            .receive_packet(link_id, packet, now_us, &mut cb_server)
                            .unwrap();
                    }
                    _ => panic!("expected relay forward to server"),
                }
            }
            while let Some(out) = server.assoc_mut().pop_outbound_packet() {
                server.assoc_mut().on_driver_complete(
                    out.link_id,
                    out.packet_number,
                    quic_link::LinkTxOutcome::Sent,
                    now_us,
                );
                let mut relay_pkt = pool.alloc().unwrap();
                relay_pkt.append(out.packet.bytes()).unwrap();
                drop(out.packet);
                match dispatch_pool_packet(&relay_registry, relay_pkt, 0, 1500).unwrap() {
                    DcidPoolPacket::Forward { rule, packet, .. } => {
                        assert_eq!(rule.next_hop, 2);
                        let (hdr, _) = ShortHeader::decode(packet.bytes()).unwrap();
                        assert_eq!(hdr.dcid, client_cid);
                        client
                            .receive_packet(link_id, packet, now_us, &mut cb_client)
                            .unwrap();
                    }
                    _ => panic!("expected relay forward to client"),
                }
            }
            now_us += 25_000;
        }

        assert_eq!(cb_server.received.as_slice(), payload);
        assert!(cb_server.fin);
        assert!(server.is_rx_fin_delivered());
        assert_eq!(client.assoc().sack_ledger().retained_packets(), 0);
        drop(client);
        drop(server);
        assert_eq!(pool.available(), usize::from(pool.slots()));
    }

    #[test]
    fn xip_relay_and_reply_tables_scale_from_small_c_defaults_to_thousands_of_host_entries() {
        // 1. Default small C-simulator limits (TABLE_MAX = 64, REPLIES = 8)
        let mut small_table = XipRelayTable::new();
        assert_eq!(small_table.max_entries(), TABLE_MAX);
        for i in 0..TABLE_MAX {
            let cid = small_table
                .table_alloc(QuicKind::Relay, 1, i as u64 + 1, &[0x55])
                .expect("within 64-entry small limit");
            assert!(!cid.is_empty());
        }
        assert_eq!(
            small_table.table_alloc(QuicKind::Relay, 1, 999, &[0x55]),
            Err(ERR_NOMEM)
        );

        // 2. Host-scale XipRelayTable (e.g. 4,096 concurrent routes + lowest-CID reuse)
        let mut host_table = XipRelayTable::host();
        assert_eq!(host_table.max_entries(), crate::xip::HOST_TABLE_MAX);
        let mut allocated = Vec::with_capacity(2_048);
        for i in 0..2_048u64 {
            let cid = host_table
                .table_alloc(QuicKind::Relay, 1, 10_000 + i, &[0x33])
                .expect("host table admits thousands of routes");
            allocated.push(cid);
        }
        assert_eq!(host_table.len(), 2_048);

        // Remove entry #5 (compact CID value 6) and entry #500; verify table_alloc reuses #5 first, then #500!
        let freed_low = allocated[5].clone();
        let freed_mid = allocated[500].clone();
        assert_eq!(host_table.table_remove(&freed_low), crate::xip::OK);
        assert_eq!(host_table.table_remove(&freed_mid), crate::xip::OK);
        let reallocated_1 = host_table
            .table_alloc(QuicKind::Local, 0, 0, &[])
            .expect("reallocate low CID");
        assert_eq!(reallocated_1, freed_low);
        let reallocated_2 = host_table
            .table_alloc(QuicKind::Local, 0, 0, &[])
            .expect("reallocate mid CID");
        assert_eq!(reallocated_2, freed_mid);

        // Also allocate 1,024 high-range managed routes via relay_create on the same host table.
        for i in 0..1_024u64 {
            let mut route = RelayRoute {
                hop_count: 1,
                ..Default::default()
            };
            route.hops[0].link = 2;
            route.hops[0].token = 50_000 + i;
            route.hops[0].weight = 1;
            route.hops[0].cid_len = 2;
            route.hops[0].rewritten_dcid[..2].copy_from_slice(&[(i >> 8) as u8, i as u8]);
            assert_eq!(
                host_table.relay_create(7, &mut route, 30_000, false, 1_000),
                Ok(0)
            );
            let selected = host_table
                .select(&route.dcid[..route.dcid_len as usize], 2_000)
                .expect("select newly created host route");
            assert_eq!(selected.token, 50_000 + i);
        }
        assert_eq!(host_table.len(), 2_048 + 1_024);

        // 3. Host-scale ReplyTable (2,048 concurrent CBOR datagram replies)
        let mut host_replies = ReplyTable::host();
        assert_eq!(host_replies.max_replies(), crate::xip::HOST_REPLIES);
        for id in 1..=1_500u64 {
            let hdr = crate::xip::QuicHeader {
                first: 0xc0,
                is_long: true,
                version: VERSION_CBOR,
                dcid: vec![0x11, (id & 0xff) as u8],
                scid: vec![0x22, ((id >> 8) & 0xff) as u8],
                body: 9,
            };
            host_replies.note(1, 0xaaaa, id, &hdr, 1_000);
        }
        assert_eq!(host_replies.len(), 1_500);
        for id in [1u64, 750, 1_500] {
            let note = host_replies
                .find(1, 0xaaaa, id, 10_000)
                .expect("reply note retained within 15s host window");
            assert_eq!(note.dcid, vec![0x22, ((id >> 8) & 0xff) as u8]);
            assert_eq!(note.scid, vec![0x11, (id & 0xff) as u8]);
        }

        // 4. Host-scale PacketRouter (16,384 routes, 512 pending setups)
        let mut host_router = PacketRouter::<u32, ForwardNextHop>::host();
        assert_eq!(host_router.registry().max_entries(), 16_384);
        for i in 1..=2_000u64 {
            let cid = ConnectionId::new(i).unwrap();
            host_router
                .register_forward(
                    cid,
                    ForwardRule {
                        next_hop: ForwardNextHop {
                            bearer: 1,
                            peer_l2_address: i,
                        },
                        destination: ForwardDestination::Connection(
                            ConnectionId::new(i + 10_000).unwrap(),
                        ),
                        lease_duration_us: 60_000_000,
                        lease_expires_at_us: 60_000_000,
                        lease_group_id: 0,
                        packet_quota: 100,
                        forwarded_packets: 0,
                        forwarded_control_packets: 0,
                        quota_window_started_us: 0,
                    },
                )
                .unwrap();
        }
        assert_eq!(host_router.route_count(), 2_000);
    }
}
