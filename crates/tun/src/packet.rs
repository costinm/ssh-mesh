use mesh::tun::TunUdpPacket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub enum TunPacket {
    Udp(TunUdpPacket),
    Tcp(TunTcpPacket),
    Other,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TunTcpPacket {
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub syn: bool,
    pub ack: bool,
}

pub fn parse_ip_packet(packet: &[u8]) -> TunPacket {
    if packet.is_empty() {
        return TunPacket::Other;
    }

    match packet[0] >> 4 {
        4 => parse_ipv4_packet(packet),
        6 => parse_ipv6_packet(packet),
        _ => TunPacket::Other,
    }
}

pub fn build_ipv4_udp_packet(
    src_addr: Ipv4Addr,
    src_port: u16,
    dst_addr: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, anyhow::Error> {
    let udp_len = 8usize
        .checked_add(payload.len())
        .ok_or_else(|| anyhow::anyhow!("UDP payload too large"))?;
    let total_len = 20usize
        .checked_add(udp_len)
        .ok_or_else(|| anyhow::anyhow!("IPv4 packet too large"))?;
    if total_len > u16::MAX as usize {
        anyhow::bail!("IPv4 packet too large: {total_len}");
    }

    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src_addr.octets());
    packet[16..20].copy_from_slice(&dst_addr.octets());
    let header_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    let udp = &mut packet[20..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);

    Ok(packet)
}

fn parse_ipv4_packet(packet: &[u8]) -> TunPacket {
    if packet.len() < 20 {
        return TunPacket::Other;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return TunPacket::Other;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < ihl || packet.len() < total_len {
        return TunPacket::Other;
    }

    let src_addr = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst_addr = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    let payload = &packet[ihl..total_len];
    match packet[9] {
        6 => parse_tcp_payload(src_addr, dst_addr, payload),
        17 => parse_udp_payload(src_addr, dst_addr, payload),
        _ => TunPacket::Other,
    }
}

pub fn ipv4_header_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    (ihl >= 20 && packet.len() >= ihl).then_some(ihl)
}

pub fn ipv4_total_len(packet: &[u8]) -> Option<usize> {
    let ihl = ipv4_header_len(packet)?;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    (total_len >= ihl && packet.len() >= total_len).then_some(total_len)
}

pub fn is_ipv4_tcp(packet: &[u8]) -> bool {
    ipv4_header_len(packet).is_some() && packet.get(9) == Some(&6)
}

pub fn rewrite_ipv4_tcp(
    packet: &[u8],
    new_src: Ipv4Addr,
    new_src_port: u16,
    new_dst: Ipv4Addr,
    new_dst_port: u16,
) -> Result<Vec<u8>, anyhow::Error> {
    if !is_ipv4_tcp(packet) {
        anyhow::bail!("packet is not IPv4 TCP");
    }
    let ihl = ipv4_header_len(packet).unwrap();
    let total_len = ipv4_total_len(packet).ok_or_else(|| anyhow::anyhow!("invalid IPv4 length"))?;
    if total_len < ihl + 20 {
        anyhow::bail!("TCP header is truncated");
    }

    let mut out = packet[..total_len].to_vec();
    out[12..16].copy_from_slice(&new_src.octets());
    out[16..20].copy_from_slice(&new_dst.octets());
    out[10..12].copy_from_slice(&[0, 0]);
    let ip_checksum = internet_checksum(&out[..ihl]);
    out[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    out[ihl..ihl + 2].copy_from_slice(&new_src_port.to_be_bytes());
    out[ihl + 2..ihl + 4].copy_from_slice(&new_dst_port.to_be_bytes());
    out[ihl + 16..ihl + 18].copy_from_slice(&[0, 0]);
    let tcp_checksum = ipv4_tcp_checksum(new_src, new_dst, &out[ihl..total_len])?;
    out[ihl + 16..ihl + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    Ok(out)
}

pub fn ipv4_checksum_valid(packet: &[u8]) -> bool {
    let Some(ihl) = ipv4_header_len(packet) else {
        return false;
    };
    internet_checksum(&packet[..ihl]) == 0
}

pub fn ipv4_tcp_checksum_valid(packet: &[u8]) -> bool {
    if !is_ipv4_tcp(packet) {
        return false;
    }
    let Some(ihl) = ipv4_header_len(packet) else {
        return false;
    };
    let Some(total_len) = ipv4_total_len(packet) else {
        return false;
    };
    if total_len < ihl + 20 {
        return false;
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    matches!(ipv4_tcp_checksum(src, dst, &packet[ihl..total_len]), Ok(0))
}

pub fn build_ipv4_tcp_packet(
    src_addr: Ipv4Addr,
    src_port: u16,
    dst_addr: Ipv4Addr,
    dst_port: u16,
    flags: u8,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Result<Vec<u8>, anyhow::Error> {
    let tcp_len = 20usize
        .checked_add(payload.len())
        .ok_or_else(|| anyhow::anyhow!("TCP payload too large"))?;
    let total_len = 20usize
        .checked_add(tcp_len)
        .ok_or_else(|| anyhow::anyhow!("IPv4 packet too large"))?;
    if total_len > u16::MAX as usize {
        anyhow::bail!("IPv4 packet too large: {total_len}");
    }

    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&src_addr.octets());
    packet[16..20].copy_from_slice(&dst_addr.octets());
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let tcp = &mut packet[20..];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
    tcp[20..].copy_from_slice(payload);
    let tcp_checksum = ipv4_tcp_checksum(src_addr, dst_addr, tcp)?;
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());

    Ok(packet)
}

fn parse_ipv6_packet(packet: &[u8]) -> TunPacket {
    if packet.len() < 40 {
        return TunPacket::Other;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = 40usize.saturating_add(payload_len);
    if packet.len() < total_len {
        return TunPacket::Other;
    }

    let mut src = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&packet[24..40]);
    let src_addr = IpAddr::V6(Ipv6Addr::from(src));
    let dst_addr = IpAddr::V6(Ipv6Addr::from(dst));
    let payload = &packet[40..total_len];
    match packet[6] {
        6 => parse_tcp_payload(src_addr, dst_addr, payload),
        17 => parse_udp_payload(src_addr, dst_addr, payload),
        _ => TunPacket::Other,
    }
}

fn parse_udp_payload(src_addr: IpAddr, dst_addr: IpAddr, payload: &[u8]) -> TunPacket {
    if payload.len() < 8 {
        return TunPacket::Other;
    }
    let udp_len = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
    if udp_len < 8 || payload.len() < udp_len {
        return TunPacket::Other;
    }

    TunPacket::Udp(TunUdpPacket {
        src_addr,
        src_port: u16::from_be_bytes([payload[0], payload[1]]),
        dst_addr,
        dst_port: u16::from_be_bytes([payload[2], payload[3]]),
        payload: payload[8..udp_len].to_vec(),
    })
}

fn parse_tcp_payload(src_addr: IpAddr, dst_addr: IpAddr, payload: &[u8]) -> TunPacket {
    if payload.len() < 20 {
        return TunPacket::Other;
    }

    TunPacket::Tcp(TunTcpPacket {
        src_addr,
        src_port: u16::from_be_bytes([payload[0], payload[1]]),
        dst_addr,
        dst_port: u16::from_be_bytes([payload[2], payload[3]]),
        syn: payload[13] & 0x02 != 0,
        ack: payload[13] & 0x10 != 0,
    })
}

fn ipv4_tcp_checksum(
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    tcp_segment: &[u8],
) -> Result<u16, anyhow::Error> {
    if tcp_segment.len() > u16::MAX as usize {
        anyhow::bail!("TCP segment too large: {}", tcp_segment.len());
    }
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len() + 1);
    pseudo.extend_from_slice(&src_addr.octets());
    pseudo.extend_from_slice(&dst_addr.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    if pseudo.len() % 2 != 0 {
        pseudo.push(0);
    }
    Ok(internet_checksum(&pseudo))
}

pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u16::from_be_bytes([byte, 0]) as u32;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}
