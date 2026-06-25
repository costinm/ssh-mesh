use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct MeshTunStats {
    pub control_capture_ok: AtomicU64,
    pub control_capture_err: AtomicU64,
    pub route_hit: AtomicU64,
    pub route_miss: AtomicU64,
    pub tap_frame_rx: AtomicU64,
    pub tap_ip_rx: AtomicU64,
    pub arp_request_rx: AtomicU64,
    pub arp_reply_tx: AtomicU64,
    pub tap_inject_packet: AtomicU64,
    pub tap_inject_error: AtomicU64,
    pub tap_last_inject_dst_mac_hi: AtomicU64,
    pub tap_last_inject_dst_mac_lo: AtomicU64,
    pub tap_last_inject_src_mac_hi: AtomicU64,
    pub tap_last_inject_src_mac_lo: AtomicU64,
    pub tap_last_inject_ethertype: AtomicU64,
    pub tap_last_inject_len: AtomicU64,
    pub tap_last_inject_write_rc: AtomicU64,
    pub tap_last_inject_ipv4_src: AtomicU64,
    pub tap_last_inject_ipv4_dst: AtomicU64,
    pub tap_last_inject_tcp_flags: AtomicU64,
    pub tap_last_inject_ip_checksum_ok: AtomicU64,
    pub tap_last_inject_tcp_checksum_ok: AtomicU64,
    pub tcp_packet: AtomicU64,
    pub tcp_syn: AtomicU64,
    pub tcp_flow_open: AtomicU64,
    pub tcp_flow_packet: AtomicU64,
    pub tcp_payload_guest_to_host: AtomicU64,
    pub tcp_payload_host_to_guest: AtomicU64,
    pub tcp_syn_ack_sent: AtomicU64,
    pub tcp_ack_after_syn: AtomicU64,
    pub tcp_handshake_skip: AtomicU64,
    pub tcp_last_handshake_flags: AtomicU64,
    pub tcp_last_handshake_seq: AtomicU64,
    pub tcp_last_handshake_ack: AtomicU64,
    pub tcp_last_handshake_expected_ack: AtomicU64,
    pub tcp_last_handshake_payload_len: AtomicU64,
    pub tcp_ack_sent: AtomicU64,
    pub tcp_data_sent: AtomicU64,
    pub tcp_fin_sent: AtomicU64,
    pub tcp_flow_close: AtomicU64,
    pub tcp_flow_error: AtomicU64,
}

static STATS: MeshTunStats = MeshTunStats {
    control_capture_ok: AtomicU64::new(0),
    control_capture_err: AtomicU64::new(0),
    route_hit: AtomicU64::new(0),
    route_miss: AtomicU64::new(0),
    tap_frame_rx: AtomicU64::new(0),
    tap_ip_rx: AtomicU64::new(0),
    arp_request_rx: AtomicU64::new(0),
    arp_reply_tx: AtomicU64::new(0),
    tap_inject_packet: AtomicU64::new(0),
    tap_inject_error: AtomicU64::new(0),
    tap_last_inject_dst_mac_hi: AtomicU64::new(0),
    tap_last_inject_dst_mac_lo: AtomicU64::new(0),
    tap_last_inject_src_mac_hi: AtomicU64::new(0),
    tap_last_inject_src_mac_lo: AtomicU64::new(0),
    tap_last_inject_ethertype: AtomicU64::new(0),
    tap_last_inject_len: AtomicU64::new(0),
    tap_last_inject_write_rc: AtomicU64::new(0),
    tap_last_inject_ipv4_src: AtomicU64::new(0),
    tap_last_inject_ipv4_dst: AtomicU64::new(0),
    tap_last_inject_tcp_flags: AtomicU64::new(0),
    tap_last_inject_ip_checksum_ok: AtomicU64::new(0),
    tap_last_inject_tcp_checksum_ok: AtomicU64::new(0),
    tcp_packet: AtomicU64::new(0),
    tcp_syn: AtomicU64::new(0),
    tcp_flow_open: AtomicU64::new(0),
    tcp_flow_packet: AtomicU64::new(0),
    tcp_payload_guest_to_host: AtomicU64::new(0),
    tcp_payload_host_to_guest: AtomicU64::new(0),
    tcp_syn_ack_sent: AtomicU64::new(0),
    tcp_ack_after_syn: AtomicU64::new(0),
    tcp_handshake_skip: AtomicU64::new(0),
    tcp_last_handshake_flags: AtomicU64::new(0),
    tcp_last_handshake_seq: AtomicU64::new(0),
    tcp_last_handshake_ack: AtomicU64::new(0),
    tcp_last_handshake_expected_ack: AtomicU64::new(0),
    tcp_last_handshake_payload_len: AtomicU64::new(0),
    tcp_ack_sent: AtomicU64::new(0),
    tcp_data_sent: AtomicU64::new(0),
    tcp_fin_sent: AtomicU64::new(0),
    tcp_flow_close: AtomicU64::new(0),
    tcp_flow_error: AtomicU64::new(0),
};

pub fn stats() -> &'static MeshTunStats {
    &STATS
}

impl MeshTunStats {
    pub fn reset(&self) {
        for counter in self.counters() {
            counter.1.store(0, Ordering::Relaxed);
        }
    }

    pub fn snapshot_lines(&self) -> Vec<String> {
        self.counters()
            .into_iter()
            .map(|(name, counter)| format!("{name}={}", counter.load(Ordering::Relaxed)))
            .collect()
    }

    fn counters(&self) -> Vec<(&'static str, &AtomicU64)> {
        vec![
            ("control_capture_ok", &self.control_capture_ok),
            ("control_capture_err", &self.control_capture_err),
            ("route_hit", &self.route_hit),
            ("route_miss", &self.route_miss),
            ("tap_frame_rx", &self.tap_frame_rx),
            ("tap_ip_rx", &self.tap_ip_rx),
            ("arp_request_rx", &self.arp_request_rx),
            ("arp_reply_tx", &self.arp_reply_tx),
            ("tap_inject_packet", &self.tap_inject_packet),
            ("tap_inject_error", &self.tap_inject_error),
            (
                "tap_last_inject_dst_mac_hi",
                &self.tap_last_inject_dst_mac_hi,
            ),
            (
                "tap_last_inject_dst_mac_lo",
                &self.tap_last_inject_dst_mac_lo,
            ),
            (
                "tap_last_inject_src_mac_hi",
                &self.tap_last_inject_src_mac_hi,
            ),
            (
                "tap_last_inject_src_mac_lo",
                &self.tap_last_inject_src_mac_lo,
            ),
            ("tap_last_inject_ethertype", &self.tap_last_inject_ethertype),
            ("tap_last_inject_len", &self.tap_last_inject_len),
            ("tap_last_inject_write_rc", &self.tap_last_inject_write_rc),
            ("tap_last_inject_ipv4_src", &self.tap_last_inject_ipv4_src),
            ("tap_last_inject_ipv4_dst", &self.tap_last_inject_ipv4_dst),
            ("tap_last_inject_tcp_flags", &self.tap_last_inject_tcp_flags),
            (
                "tap_last_inject_ip_checksum_ok",
                &self.tap_last_inject_ip_checksum_ok,
            ),
            (
                "tap_last_inject_tcp_checksum_ok",
                &self.tap_last_inject_tcp_checksum_ok,
            ),
            ("tcp_packet", &self.tcp_packet),
            ("tcp_syn", &self.tcp_syn),
            ("tcp_flow_open", &self.tcp_flow_open),
            ("tcp_flow_packet", &self.tcp_flow_packet),
            ("tcp_payload_guest_to_host", &self.tcp_payload_guest_to_host),
            ("tcp_payload_host_to_guest", &self.tcp_payload_host_to_guest),
            ("tcp_syn_ack_sent", &self.tcp_syn_ack_sent),
            ("tcp_ack_after_syn", &self.tcp_ack_after_syn),
            ("tcp_handshake_skip", &self.tcp_handshake_skip),
            ("tcp_last_handshake_flags", &self.tcp_last_handshake_flags),
            ("tcp_last_handshake_seq", &self.tcp_last_handshake_seq),
            ("tcp_last_handshake_ack", &self.tcp_last_handshake_ack),
            (
                "tcp_last_handshake_expected_ack",
                &self.tcp_last_handshake_expected_ack,
            ),
            (
                "tcp_last_handshake_payload_len",
                &self.tcp_last_handshake_payload_len,
            ),
            ("tcp_ack_sent", &self.tcp_ack_sent),
            ("tcp_data_sent", &self.tcp_data_sent),
            ("tcp_fin_sent", &self.tcp_fin_sent),
            ("tcp_flow_close", &self.tcp_flow_close),
            ("tcp_flow_error", &self.tcp_flow_error),
        ]
    }
}
