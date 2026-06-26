use std::io::{BufRead, BufReader, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::UnixListener;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct ControlServerConfig {
    pub socket_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct BwrapInfoServerConfig {
    pub if_name: String,
    pub network: Ipv4Addr,
    pub prefix_len: u8,
    pub first_host: u32,
    pub gateway: String,
    pub vm_id: String,
}

struct BwrapInfoServerState {
    config: BwrapInfoServerConfig,
    next_host: AtomicU32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TapCaptureSpec {
    pub vm_id: String,
    pub netns_path: PathBuf,
    pub if_name: Option<String>,
    pub setup: Option<NetnsSetup>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetnsSetup {
    pub address: Option<String>,
    pub gateway: Option<String>,
    pub default_route: bool,
}

pub async fn run_control_server(
    listener: UnixListener,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    tracing::info!(addr = ?listener.local_addr(), "mesh-tun control socket started");

    loop {
        let (stream, _) = listener.accept().await?;
        let tun_tx = tun_tx.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_control_client(stream, tun_tx).await {
                tracing::warn!(%error, "mesh-tun control client disconnected");
            }
        });
    }
}

pub async fn run_bwrap_info_server(
    listener: UnixListener,
    config: BwrapInfoServerConfig,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    tracing::info!(addr = ?listener.local_addr(), "mesh-tun bwrap info socket started");
    let state = Arc::new(BwrapInfoServerState {
        next_host: AtomicU32::new(config.first_host),
        config,
    });

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        let tun_tx = tun_tx.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_bwrap_info_client(stream, state, tun_tx).await {
                tracing::warn!(%error, "mesh-tun bwrap info client disconnected");
            }
        });
    }
}

async fn handle_control_client(
    stream: tokio::net::UnixStream,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    let std_stream = stream.into_std()?;
    std_stream.set_nonblocking(false)?;
    tokio::task::spawn_blocking(move || {
        let reader_stream = std_stream.try_clone()?;
        let mut reader = BufReader::new(reader_stream);
        let mut writer = std_stream;
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                return Ok::<(), anyhow::Error>(());
            }
            let request = line.trim();
            if request.is_empty() {
                continue;
            }
            match parse_control_request(request) {
                Ok(ControlRequest::CaptureTap(spec)) => {
                    let result = start_tap_capture(spec, tun_tx.clone());
                    match result {
                        Ok(()) => {
                            crate::stats::stats()
                                .control_capture_ok
                                .fetch_add(1, Ordering::Relaxed);
                            writeln!(writer, "ok")?
                        }
                        Err(error) => {
                            crate::stats::stats()
                                .control_capture_err
                                .fetch_add(1, Ordering::Relaxed);
                            writeln!(writer, "error {error}")?
                        }
                    }
                }
                Ok(ControlRequest::Ping) => {
                    writeln!(writer, "ok pong")?;
                }
                Ok(ControlRequest::Stats) => {
                    writeln!(
                        writer,
                        "ok {}",
                        crate::stats::stats().snapshot_lines().join(" ")
                    )?;
                }
                Ok(ControlRequest::ResetStats) => {
                    crate::stats::stats().reset();
                    writeln!(writer, "ok")?;
                }
                Err(error) => {
                    writeln!(writer, "error {error}")?;
                }
            }
            writer.flush()?;
        }
    })
    .await?
}

async fn handle_bwrap_info_client(
    stream: tokio::net::UnixStream,
    state: Arc<BwrapInfoServerState>,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    let mut stream = stream.into_std()?;
    stream.set_nonblocking(false)?;
    tokio::task::spawn_blocking(move || {
        let info = read_bwrap_info(&mut stream)?;
        let child_pid = parse_bwrap_child_pid(&info)
            .ok_or_else(|| anyhow::anyhow!("bwrap info did not include child-pid: {info}"))?;
        let guest_ip = state.allocate_guest_ip()?;
        let config = &state.config;
        let spec = TapCaptureSpec {
            vm_id: config.vm_id.clone(),
            netns_path: PathBuf::from(format!("/proc/{child_pid}/ns/net")),
            if_name: Some(config.if_name.clone()),
            setup: Some(NetnsSetup {
                address: Some(format!("{guest_ip}/{}", config.prefix_len)),
                gateway: Some(config.gateway.clone()),
                default_route: true,
            }),
        };

        start_tap_capture(spec, tun_tx)?;
        crate::stats::stats()
            .control_capture_ok
            .fetch_add(1, Ordering::Relaxed);
        stream.write_all(b"x")?;
        stream.flush()?;
        Ok::<(), anyhow::Error>(())
    })
    .await?
}

impl BwrapInfoServerState {
    fn allocate_guest_ip(&self) -> Result<Ipv4Addr, anyhow::Error> {
        let host = self.next_host.fetch_add(1, Ordering::Relaxed);
        let prefix_len = self.config.prefix_len;
        let host_bits = 32u8.saturating_sub(prefix_len);
        if host_bits < 32 && host >= (1u32 << host_bits).saturating_sub(1) {
            anyhow::bail!("bwrap IPv4 pool exhausted");
        }

        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        let network = u32::from(self.config.network) & mask;
        Ok(Ipv4Addr::from(network | host))
    }
}

fn read_bwrap_info(stream: &mut std::os::unix::net::UnixStream) -> Result<String, anyhow::Error> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut info = String::new();
    let mut buf = [0u8; 512];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        info.push_str(&String::from_utf8_lossy(&buf[..n]));
        if parse_bwrap_child_pid(&info).is_some() {
            return Ok(info);
        }
    }
    Ok(info)
}

fn parse_bwrap_child_pid(info: &str) -> Option<u32> {
    let marker = "\"child-pid\"";
    let after_marker = info.split(marker).nth(1)?;
    let after_colon = after_marker.split(':').nth(1)?;
    let digits: String = after_colon
        .chars()
        .skip_while(|ch| ch.is_whitespace())
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

enum ControlRequest {
    Ping,
    Stats,
    ResetStats,
    CaptureTap(TapCaptureSpec),
}

fn parse_control_request(request: &str) -> Result<ControlRequest, anyhow::Error> {
    let mut fields = request.split_whitespace();
    match fields.next() {
        Some("ping") => Ok(ControlRequest::Ping),
        Some("stats") => Ok(ControlRequest::Stats),
        Some("reset-stats") => Ok(ControlRequest::ResetStats),
        Some("capture-tap") => {
            let mut vm_id = None;
            let mut netns_path = None;
            let mut if_name = None;
            let mut setup = None;
            let mut address = None;
            let mut gateway = None;
            let mut default_route = false;
            for field in fields {
                let Some((key, value)) = field.split_once('=') else {
                    anyhow::bail!("expected key=value field, got {field}");
                };
                match key {
                    "vm_id" => vm_id = Some(value.to_string()),
                    "netns" => netns_path = Some(PathBuf::from(value)),
                    "if" => if_name = Some(value.to_string()),
                    "gw" => gateway = Some(value.to_string()),
                    "setup" => match value {
                        "tap" => setup = Some(()),
                        other => anyhow::bail!("unsupported setup={other}"),
                    },
                    "addr" => address = Some(value.to_string()),
                    "route" => {
                        default_route = match value {
                            "default" => true,
                            "none" => false,
                            other => anyhow::bail!("unsupported route={other}"),
                        };
                    }
                    other => anyhow::bail!("unknown capture-tap field {other}"),
                }
            }
            let setup = setup.map(|()| NetnsSetup {
                address,
                gateway,
                default_route,
            });
            Ok(ControlRequest::CaptureTap(TapCaptureSpec {
                vm_id: vm_id.unwrap_or_else(|| "netns".to_string()),
                netns_path: netns_path
                    .ok_or_else(|| anyhow::anyhow!("capture-tap requires netns=/path"))?,
                if_name,
                setup,
            }))
        }
        Some(other) => anyhow::bail!("unknown control command {other}"),
        None => anyhow::bail!("empty control command"),
    }
}

static GUEST_ROUTER: std::sync::OnceLock<
    std::sync::RwLock<std::collections::HashMap<std::net::IpAddr, mpsc::Sender<Vec<u8>>>>,
> = std::sync::OnceLock::new();

pub fn register_destination(ip: std::net::IpAddr, sender: mpsc::Sender<Vec<u8>>) {
    GUEST_ROUTER
        .get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()))
        .write()
        .unwrap()
        .insert(ip, sender);
}

pub fn unregister_destination(ip: &std::net::IpAddr) {
    if let Some(registry) = GUEST_ROUTER.get() {
        registry.write().unwrap().remove(ip);
    }
}

pub fn route_outgoing_packet(packet: &[u8]) -> bool {
    let dst_ip = match get_destination_ip(packet) {
        Some(ip) => ip,
        None => return false,
    };
    if let Some(registry) = GUEST_ROUTER.get() {
        if let Some(sender) = registry.read().unwrap().get(&dst_ip) {
            match sender.try_send(packet.to_vec()) {
                Ok(()) => {
                    crate::stats::stats()
                        .route_hit
                        .fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    crate::stats::stats()
                        .route_send_full
                        .fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            }
        }
    }
    crate::stats::stats()
        .route_miss
        .fetch_add(1, Ordering::Relaxed);
    false
}

fn get_source_ip(packet: &[u8]) -> Option<std::net::IpAddr> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&packet[12..16]);
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(addr)))
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&packet[8..24]);
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr)))
        }
        _ => None,
    }
}

fn get_destination_ip(packet: &[u8]) -> Option<std::net::IpAddr> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&packet[16..20]);
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(addr)))
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&packet[24..40]);
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr)))
        }
        _ => None,
    }
}

fn start_tap_capture(
    spec: TapCaptureSpec,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    let spec = Arc::new(spec);
    let (inject_tx, inject_rx) = mpsc::channel::<Vec<u8>>(1024);
    let guest_mac = Arc::new(std::sync::Mutex::new(None));

    let socket = fork_and_create_tap(&spec)?;
    let socket_arc = Arc::new(socket);

    std::thread::Builder::new()
        .name(format!("mesh-tun-tap-{}", spec.vm_id))
        .spawn(move || {
            if let Err(error) = packet_capture_thread_loop(
                &spec, socket_arc, tun_tx, guest_mac, inject_tx, inject_rx,
            ) {
                tracing::warn!(vm_id = %spec.vm_id, %error, "TAP capture loop stopped");
            }
        })?;

    Ok(())
}

fn inject_ip_packet(
    socket: &OwnedFd,
    guest_mac: Arc<std::sync::Mutex<Option<[u8; 6]>>>,
    ip_packet: &[u8],
) -> Result<(), anyhow::Error> {
    let gateway_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

    crate::stats::stats()
        .tap_inject_packet
        .fetch_add(1, Ordering::Relaxed);
    let dst_mac = {
        let guard = guest_mac.lock().unwrap();
        guard.unwrap_or([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    };
    let src_mac = if dst_mac == [0, 0, 0, 0, 0, 0] {
        dst_mac
    } else {
        gateway_mac
    };

    let ethertype = match ip_packet[0] >> 4 {
        4 => 0x0800u16,
        6 => 0x86ddu16,
        _ => return Ok(()),
    };

    let mut frame = Vec::with_capacity(14 + ip_packet.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(ip_packet);
    if frame.len() < 60 {
        frame.resize(60, 0);
    }

    record_inject_frame(&frame);
    let rc = unsafe { libc::write(socket.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
    crate::stats::stats()
        .tap_last_inject_write_rc
        .store(rc.max(0) as u64, Ordering::Relaxed);
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EBADF) {
            crate::stats::stats()
                .tap_inject_error
                .fetch_add(1, Ordering::Relaxed);
            tracing::error!("TAP inject failed: {}", err);
        }
        return Err(err.into());
    }
    Ok(())
}

fn record_inject_frame(frame: &[u8]) {
    if frame.len() < 14 {
        return;
    }
    let stats = crate::stats::stats();
    stats
        .tap_last_inject_dst_mac_hi
        .store(mac_hi(&frame[0..6]), Ordering::Relaxed);
    stats
        .tap_last_inject_dst_mac_lo
        .store(mac_lo(&frame[0..6]), Ordering::Relaxed);
    stats
        .tap_last_inject_src_mac_hi
        .store(mac_hi(&frame[6..12]), Ordering::Relaxed);
    stats
        .tap_last_inject_src_mac_lo
        .store(mac_lo(&frame[6..12]), Ordering::Relaxed);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    stats
        .tap_last_inject_ethertype
        .store(u64::from(ethertype), Ordering::Relaxed);
    stats
        .tap_last_inject_len
        .store(frame.len() as u64, Ordering::Relaxed);

    if ethertype == 0x0800 && frame.len() >= 54 {
        let ip = &frame[14..];
        let ihl = usize::from(ip[0] & 0x0f) * 4;
        stats
            .tap_last_inject_ip_checksum_ok
            .store(u64::from(ipv4_header_checksum_valid(ip)), Ordering::Relaxed);
        if ihl >= 20 && ip.len() >= ihl + 20 && ip[9] == 6 {
            stats.tap_last_inject_ipv4_src.store(
                u64::from(u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]])),
                Ordering::Relaxed,
            );
            stats.tap_last_inject_ipv4_dst.store(
                u64::from(u32::from_be_bytes([ip[16], ip[17], ip[18], ip[19]])),
                Ordering::Relaxed,
            );
            stats
                .tap_last_inject_tcp_flags
                .store(u64::from(ip[ihl + 13]), Ordering::Relaxed);
            stats.tap_last_inject_tcp_checksum_ok.store(
                u64::from(ipv4_tcp_checksum_valid(ip, ihl)),
                Ordering::Relaxed,
            );
        }
    }
}

fn mac_hi(mac: &[u8]) -> u64 {
    (u64::from(mac[0]) << 16) | (u64::from(mac[1]) << 8) | u64::from(mac[2])
}

fn mac_lo(mac: &[u8]) -> u64 {
    (u64::from(mac[3]) << 16) | (u64::from(mac[4]) << 8) | u64::from(mac[5])
}

fn ipv4_header_checksum_valid(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    ihl >= 20 && packet.len() >= ihl && internet_checksum(&packet[..ihl]) == 0
}

fn ipv4_tcp_checksum_valid(packet: &[u8], ihl: usize) -> bool {
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if packet.len() < total_len || total_len < ihl + 20 || packet[9] != 6 {
        return false;
    }

    let tcp = &packet[ihl..total_len];
    let tcp_len = tcp.len() as u32;
    let mut sum = 0u32;
    sum = checksum_add(sum, &packet[12..16]);
    sum = checksum_add(sum, &packet[16..20]);
    sum += 6;
    sum += tcp_len;
    sum = checksum_add(sum, tcp);
    checksum_finish(sum) == 0
}

fn internet_checksum(buf: &[u8]) -> u16 {
    checksum_finish(checksum_add(0, buf))
}

fn checksum_add(mut sum: u32, buf: &[u8]) -> u32 {
    for chunk in buf.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
    }
    sum
}

fn checksum_finish(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn packet_capture_thread_loop(
    _spec: &TapCaptureSpec,
    socket_arc: Arc<OwnedFd>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    guest_mac: Arc<std::sync::Mutex<Option<[u8; 6]>>>,
    inject_tx: mpsc::Sender<Vec<u8>>,
    mut inject_rx: mpsc::Receiver<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    let mut buf = vec![0u8; 65535];
    let mut registered_ips = std::collections::HashSet::new();

    loop {
        drain_inject_queue(&socket_arc, guest_mac.clone(), &mut inject_rx)?;

        let mut poll_fd = libc::pollfd {
            fd: socket_arc.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll_fd, 1, 10) };
        if ready < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if ready == 0 {
            continue;
        }
        if poll_fd.revents & libc::POLLIN == 0 {
            continue;
        }

        let n = unsafe { libc::read(socket_arc.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EBADF) {
                break;
            }
            return Err(err.into());
        }
        let n = n as usize;
        crate::stats::stats()
            .tap_frame_rx
            .fetch_add(1, Ordering::Relaxed);
        if n < 14 {
            continue;
        }

        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&buf[6..12]);
        *guest_mac.lock().unwrap() = Some(src_mac);

        if let Some(reply) = arp_reply(&buf[..n]) {
            crate::stats::stats()
                .arp_request_rx
                .fetch_add(1, Ordering::Relaxed);
            let rc =
                unsafe { libc::write(socket_arc.as_raw_fd(), reply.as_ptr().cast(), reply.len()) };
            if rc >= 0 {
                crate::stats::stats()
                    .arp_reply_tx
                    .fetch_add(1, Ordering::Relaxed);
            }
            continue;
        }

        if let Some(ip_packet) = ethernet_payload_to_ip(&buf[..n]) {
            crate::stats::stats()
                .tap_ip_rx
                .fetch_add(1, Ordering::Relaxed);
            if let Some(src_ip) = get_source_ip(&ip_packet) {
                if registered_ips.insert(src_ip) {
                    register_destination(src_ip, inject_tx.clone());
                }
            }

            match tun_tx.try_send(ip_packet) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    crate::stats::stats()
                        .tun_input_queue_full
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(anyhow::anyhow!("TUN input queue closed"));
                }
            }
        }
    }

    for ip in registered_ips {
        unregister_destination(&ip);
    }

    Ok(())
}

fn drain_inject_queue(
    socket: &OwnedFd,
    guest_mac: Arc<std::sync::Mutex<Option<[u8; 6]>>>,
    inject_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    loop {
        match inject_rx.try_recv() {
            Ok(packet) => inject_ip_packet(socket, guest_mac.clone(), &packet)?,
            Err(mpsc::error::TryRecvError::Empty) => return Ok(()),
            Err(mpsc::error::TryRecvError::Disconnected) => return Ok(()),
        }
    }
}

fn fork_and_create_tap(spec: &TapCaptureSpec) -> Result<OwnedFd, anyhow::Error> {
    use std::os::fd::FromRawFd;

    // Create a socketpair for passing the file descriptor
    let mut fds = [0i32; 2];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let parent_sock = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let child_sock = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    // Find the user namespace path by looking up the sibling user namespace
    // For netns "/proc/<pid>/ns/net", the corresponding user namespace is "/proc/<pid>/ns/user"
    let userns_path = if let Some(parent_dir) = spec.netns_path.parent() {
        parent_dir.join("user")
    } else {
        PathBuf::from("/invalid/path")
    };

    let self_userns = std::fs::metadata("/proc/self/ns/user");
    let target_userns = std::fs::metadata(&userns_path);
    let should_enter_userns = match (self_userns, target_userns) {
        (Ok(s), Ok(t)) => {
            use std::os::unix::fs::MetadataExt;
            s.ino() != t.ino()
        }
        _ => false,
    };

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    if pid == 0 {
        // In the child process:
        // Note: The child process is single-threaded, so it can safely call setns(..., CLONE_NEWUSER)
        drop(parent_sock);

        let run_child = || -> Result<(), std::io::Error> {
            // Unshare filesystem state to avoid sharing context with parent threads
            let rc = unsafe { libc::unshare(libc::CLONE_FS) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }

            // First, enter the user namespace of the target process if it is different
            // This is crucial because it gives us capabilities (like CAP_NET_ADMIN/CAP_SYS_ADMIN) inside that namespace
            if should_enter_userns && userns_path.exists() {
                let userns_file = std::fs::File::open(&userns_path)?;
                let rc = unsafe { libc::setns(userns_file.as_raw_fd(), libc::CLONE_NEWUSER) };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            // Enter the network namespace
            let netns_file = std::fs::File::open(&spec.netns_path)?;
            let rc = unsafe { libc::setns(netns_file.as_raw_fd(), libc::CLONE_NEWNET) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }

            let if_name = spec.if_name.as_deref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "capture-tap requires if=NAME",
                )
            })?;
            let tap_fd = open_tap_device(if_name)?;

            if let Some(setup) = &spec.setup {
                configure_netns_interface(if_name, setup)?;
            } else {
                run_ip(&["link", "set", "dev", "lo", "up"], true)?;
                run_ip(&["link", "set", "dev", if_name, "up"], false)?;
            }

            send_fd(child_sock.as_raw_fd(), tap_fd.as_raw_fd())?;
            Ok(())
        };

        match run_child() {
            Ok(()) => unsafe { libc::_exit(0) },
            Err(e) => {
                let code = e.raw_os_error().unwrap_or(255);
                unsafe { libc::_exit(code) }
            }
        }
    }

    // In the parent process:
    drop(child_sock);

    // Wait for the child to exit
    let mut status = 0i32;
    let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    if libc::WIFEXITED(status) {
        let exit_code = libc::WEXITSTATUS(status);
        if exit_code != 0 {
            return Err(std::io::Error::from_raw_os_error(exit_code).into());
        }
    } else {
        anyhow::bail!("child process terminated abnormally");
    }

    // Receive FD
    let fd = recv_fd(parent_sock.as_raw_fd())?;
    Ok(fd)
}

fn configure_netns_interface(if_name: &str, setup: &NetnsSetup) -> Result<(), std::io::Error> {
    run_ip(&["link", "set", "dev", "lo", "up"], true)?;

    if let Some(address) = &setup.address {
        run_ip(&["addr", "add", address, "dev", if_name], true)?;
    }

    run_ip(&["link", "set", "dev", if_name, "up"], false)?;

    if setup.default_route {
        if let Some(gateway) = &setup.gateway {
            run_ip(
                &["route", "add", "default", "via", gateway, "dev", if_name],
                true,
            )?;
        } else {
            run_ip(&["route", "add", "default", "dev", if_name], true)?;
        }
    }

    Ok(())
}

fn open_tap_device(if_name: &str) -> Result<OwnedFd, std::io::Error> {
    use std::os::fd::FromRawFd;

    let name = std::ffi::CString::new(if_name)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid if name"))?;
    if name.as_bytes_with_nul().len() > libc::IFNAMSIZ {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }

    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            req.ifr_name.as_mut_ptr(),
            name.as_bytes_with_nul().len(),
        );
        req.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;
    }

    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut req) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(fd)
}

fn run_ip(args: &[&str], allow_existing: bool) -> Result<(), std::io::Error> {
    let output = std::process::Command::new("ip").args(args).output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if allow_existing
        && (stderr.contains("File exists") || stderr.contains("RTNETLINK answers: File exists"))
    {
        return Ok(());
    }

    Err(std::io::Error::other(format!(
        "ip {} failed: {}",
        args.join(" "),
        stderr.trim()
    )))
}

fn send_fd(sock: RawFd, fd: RawFd) -> Result<(), std::io::Error> {
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };

    // We must send at least one dummy byte of data for sendmsg to succeed on many platforms
    let mut dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: (&mut dummy as *mut u8).cast(),
        iov_len: 1,
    };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    // Allocate control message buffer for the file descriptor
    let mut control_buf =
        [0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize }];
    msg.msg_control = control_buf.as_mut_ptr().cast();
    msg.msg_controllen = control_buf.len() as _;

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(std::io::Error::other("CMSG_FIRSTHDR failed"));
    }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        let data_ptr = libc::CMSG_DATA(cmsg);
        std::ptr::write(data_ptr.cast::<RawFd>(), fd);
    }

    let rc = unsafe { libc::sendmsg(sock, &msg, 0) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn recv_fd(sock: RawFd) -> Result<OwnedFd, std::io::Error> {
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };

    let mut dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: (&mut dummy as *mut u8).cast(),
        iov_len: 1,
    };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    let mut control_buf =
        [0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize }];
    msg.msg_control = control_buf.as_mut_ptr().cast();
    msg.msg_controllen = control_buf.len() as _;

    let rc = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(std::io::Error::other("no control message received"));
    }

    let cmsg_level = unsafe { std::ptr::addr_of!((*cmsg).cmsg_level).read_unaligned() };
    let cmsg_type = unsafe { std::ptr::addr_of!((*cmsg).cmsg_type).read_unaligned() };
    let is_scm_rights = cmsg_level == libc::SOL_SOCKET && cmsg_type == libc::SCM_RIGHTS;
    if !is_scm_rights {
        return Err(std::io::Error::other("expected SCM_RIGHTS"));
    }

    let fd = unsafe { libc::CMSG_DATA(cmsg).cast::<RawFd>().read_unaligned() };
    if fd < 0 {
        return Err(std::io::Error::other("invalid file descriptor received"));
    }

    use std::os::fd::FromRawFd;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn arp_reply(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 42 || u16::from_be_bytes([frame[12], frame[13]]) != 0x0806 {
        return None;
    }
    let arp = &frame[14..42];
    let htype = u16::from_be_bytes([arp[0], arp[1]]);
    let ptype = u16::from_be_bytes([arp[2], arp[3]]);
    let hlen = arp[4];
    let plen = arp[5];
    let op = u16::from_be_bytes([arp[6], arp[7]]);
    if htype != 1 || ptype != 0x0800 || hlen != 6 || plen != 4 || op != 1 {
        return None;
    }

    let gateway_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let sender_mac = &arp[8..14];
    let sender_ip = &arp[14..18];
    let target_ip = &arp[24..28];

    let mut reply = vec![0u8; 42];
    reply[0..6].copy_from_slice(sender_mac);
    reply[6..12].copy_from_slice(&gateway_mac);
    reply[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    reply[14..16].copy_from_slice(&1u16.to_be_bytes());
    reply[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    reply[18] = 6;
    reply[19] = 4;
    reply[20..22].copy_from_slice(&2u16.to_be_bytes());
    reply[22..28].copy_from_slice(&gateway_mac);
    reply[28..32].copy_from_slice(target_ip);
    reply[32..38].copy_from_slice(sender_mac);
    reply[38..42].copy_from_slice(sender_ip);
    Some(reply)
}

fn ethernet_payload_to_ip(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 14 {
        return None;
    }
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0800 => {
            let payload = &frame[14..];
            if payload.len() < 20 {
                return None;
            }
            let ihl = usize::from(payload[0] & 0x0f) * 4;
            if ihl < 20 || payload.len() < ihl {
                return None;
            }
            let total_len = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
            if total_len >= ihl && payload.len() >= total_len {
                Some(payload[..total_len].to_vec())
            } else {
                Some(payload.to_vec())
            }
        }
        0x86dd => {
            let payload = &frame[14..];
            if payload.len() < 40 {
                return None;
            }
            let payload_len = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
            let total_len = 40usize.saturating_add(payload_len);
            if payload.len() >= total_len {
                Some(payload[..total_len].to_vec())
            } else {
                Some(payload.to_vec())
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tap_capture_command() {
        let ControlRequest::CaptureTap(spec) = parse_control_request(
            "capture-tap vm_id=app5 netns=/proc/791/ns/net if=tap0 setup=tap addr=10.5.0.2/24 gw=10.5.0.1 route=default",
        )
        .unwrap()
        else {
            panic!("expected capture-tap");
        };
        assert_eq!(spec.vm_id, "app5");
        assert_eq!(spec.netns_path, PathBuf::from("/proc/791/ns/net"));
        assert_eq!(spec.if_name.as_deref(), Some("tap0"));
        assert_eq!(
            spec.setup,
            Some(NetnsSetup {
                address: Some("10.5.0.2/24".to_string()),
                gateway: Some("10.5.0.1".to_string()),
                default_route: true,
            })
        );
    }

    #[test]
    fn route_outgoing_packet_counts_full_destination_queue() {
        crate::stats::stats().reset();
        let dst = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 250, 0, 2));
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
        register_destination(dst, tx);

        let first = crate::packet::build_ipv4_udp_packet(
            std::net::Ipv4Addr::new(192, 0, 2, 10),
            1234,
            std::net::Ipv4Addr::new(10, 250, 0, 2),
            5678,
            b"first",
        )
        .unwrap();
        let second = crate::packet::build_ipv4_udp_packet(
            std::net::Ipv4Addr::new(192, 0, 2, 10),
            1234,
            std::net::Ipv4Addr::new(10, 250, 0, 2),
            5678,
            b"second",
        )
        .unwrap();

        assert!(route_outgoing_packet(&first));
        assert!(route_outgoing_packet(&second));
        assert_eq!(
            crate::stats::stats()
                .route_send_full
                .load(Ordering::Relaxed),
            1
        );

        unregister_destination(&dst);
        let _ = rx.try_recv();
    }
}
