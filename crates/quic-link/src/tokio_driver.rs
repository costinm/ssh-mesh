//! Multi-link Tokio driver for [`QuicLinkAssoc`] over [`mesh_api::link::PacketLink`] drivers.

use std::boxed::Box;
use std::collections::{BTreeMap, VecDeque};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec::Vec;

use mesh_api::link::{
    LinkInfo, LinkIngress, LinkMeta, LinkName, LinkTxOutcome, PacketLink, PeerL2Address,
};
use quic_base::{
    AssociationEgress, DEFAULT_HEADROOM, DEFAULT_MAX_PAYLOAD, LinkSendError, PacketPool,
    PoolPacket, StreamPriority, TxPacketMeta, XipLazyPacket, XipLazyPool,
};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

use crate::{AssocConfig, LinkId, LinkProfile, QuicLinkAssoc, TokioUdpLink};

const MAX_TX_BATCH: usize = 8;
const MAX_RX_BATCH: usize = 16;
const RETRY_MIN_BACKOFF_US: u64 = 2_000;
const RETRY_MAX_BACKOFF_US: u64 = 50_000;
const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// [`LinkIngress`] implementation forwarding received packets into [`TokioAssocDriver`].
pub struct TokioLinkIngress {
    link_id: LinkId,
    tx: mpsc::UnboundedSender<(LinkId, LinkMeta, XipLazyPacket)>,
    tx_notify: Arc<Notify>,
}

impl LinkIngress<XipLazyPacket> for TokioLinkIngress {
    fn on_packet(&self, meta: LinkMeta, packet: XipLazyPacket) {
        let _ = self.tx.send((self.link_id, meta, packet));
    }

    fn on_tx_ready(&self) {
        self.tx_notify.notify_one();
    }
}

struct AttachedLink {
    id: LinkId,
    peer: PeerL2Address,
    profile: LinkProfile,
    driver: Box<dyn PacketLink<XipLazyPacket> + Send>,
    pending_tx: VecDeque<(u32, XipLazyPacket)>,
    blocked: bool,
    rx_task: Option<JoinHandle<()>>,
}

impl Drop for AttachedLink {
    fn drop(&mut self) {
        if let Some(task) = self.rx_task.take() {
            task.abort();
        }
    }
}

/// Multi-link Tokio driver bridging `TokioMux` byte-frame channels to [`QuicLinkAssoc`].
pub struct TokioAssocDriver {
    assoc_config: AssocConfig,
    channel_capacity: usize,
    pool: XipLazyPool,
    rx_tx: mpsc::UnboundedSender<(LinkId, LinkMeta, XipLazyPacket)>,
    rx_rx: mpsc::UnboundedReceiver<(LinkId, LinkMeta, XipLazyPacket)>,
    tx_notify: Arc<Notify>,
    links: Vec<AttachedLink>,
}

impl TokioAssocDriver {
    /// Create a new multi-link association driver with its own [`XipLazyPool`].
    pub fn new(assoc_config: AssocConfig, channel_capacity: usize) -> Self {
        let (rx_tx, rx_rx) = mpsc::unbounded_channel();
        Self {
            assoc_config,
            channel_capacity: channel_capacity.max(16),
            pool: XipLazyPool::with_default_geometry(256),
            rx_tx,
            rx_rx,
            tx_notify: Arc::new(Notify::new()),
            links: Vec::new(),
        }
    }

    /// Pool used by attached link drivers when allocating inbound packets.
    pub fn pool(&self) -> XipLazyPool {
        self.pool.clone()
    }

    fn insert_link(&mut self, attached: AttachedLink) {
        if let Some(existing) = self.links.iter_mut().find(|l| l.id == attached.id) {
            tracing::warn!(
                link_id = attached.id.0,
                "replacing duplicate LinkId in TokioAssocDriver"
            );
            *existing = attached;
        } else {
            self.links.push(attached);
        }
    }

    /// Attach one [`PacketLink`] driver and return its [`LinkIngress`] handle.
    pub fn add_link(
        &mut self,
        id: LinkId,
        peer: PeerL2Address,
        profile: LinkProfile,
        driver: impl PacketLink<XipLazyPacket> + Send + 'static,
    ) -> Arc<dyn LinkIngress<XipLazyPacket>> {
        self.add_link_internal(id, peer, profile, Box::new(driver), None)
    }

    fn add_link_internal(
        &mut self,
        id: LinkId,
        peer: PeerL2Address,
        profile: LinkProfile,
        driver: Box<dyn PacketLink<XipLazyPacket> + Send>,
        rx_task: Option<JoinHandle<()>>,
    ) -> Arc<dyn LinkIngress<XipLazyPacket>> {
        self.insert_link(AttachedLink {
            id,
            peer,
            profile,
            driver,
            pending_tx: VecDeque::new(),
            blocked: false,
            rx_task,
        });
        Arc::new(TokioLinkIngress {
            link_id: id,
            tx: self.rx_tx.clone(),
            tx_notify: self.tx_notify.clone(),
        })
    }

    /// Construct and attach a [`PacketLink`] driver that needs the driver pool and its
    /// [`LinkIngress`] during initialization (for example UART or BLE reader tasks).
    pub fn add_link_with<L, E, F>(
        &mut self,
        id: LinkId,
        peer: PeerL2Address,
        profile: LinkProfile,
        build: F,
    ) -> Result<(), E>
    where
        L: PacketLink<XipLazyPacket> + Send + 'static,
        F: FnOnce(XipLazyPool, Arc<dyn LinkIngress<XipLazyPacket>>) -> Result<L, E>,
    {
        let ingress: Arc<dyn LinkIngress<XipLazyPacket>> = Arc::new(TokioLinkIngress {
            link_id: id,
            tx: self.rx_tx.clone(),
            tx_notify: self.tx_notify.clone(),
        });
        let driver = build(self.pool.clone(), ingress)?;
        self.insert_link(AttachedLink {
            id,
            peer,
            profile,
            driver: Box::new(driver),
            pending_tx: VecDeque::new(),
            blocked: false,
            rx_task: None,
        });
        Ok(())
    }

    /// Attach a [`TokioUdpLink`] targeting `peer` to this multi-link association driver.
    pub fn add_udp_link(
        &mut self,
        id: LinkId,
        udp_link: TokioUdpLink,
        peer: SocketAddr,
        profile: LinkProfile,
    ) {
        struct UdpPacketLink {
            udp: Arc<TokioUdpLink>,
            peer: SocketAddr,
            info: LinkInfo,
        }
        impl PacketLink<XipLazyPacket> for UdpPacketLink {
            fn info(&self) -> &LinkInfo {
                &self.info
            }
            fn send_packet(
                &mut self,
                _peer: PeerL2Address,
                packet: XipLazyPacket,
            ) -> Result<LinkTxOutcome, XipLazyPacket> {
                match self.udp.try_send_packet(&packet, self.peer) {
                    Ok(outcome) => Ok(outcome),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => Err(packet),
                    Err(e) => {
                        tracing::debug!(
                            error = %e,
                            peer = %self.peer,
                            "UDP try_send_packet failed"
                        );
                        Ok(LinkTxOutcome::Failed)
                    }
                }
            }
        }
        let udp = Arc::new(udp_link);
        let rx_udp = udp.clone();
        let pool = self.pool.clone();
        let l2_peer = PeerL2Address::new(1).expect("non-zero");
        let ingress: Arc<dyn LinkIngress<XipLazyPacket>> = Arc::new(TokioLinkIngress {
            link_id: id,
            tx: self.rx_tx.clone(),
            tx_notify: self.tx_notify.clone(),
        });
        let rx_probe = self.rx_tx.clone();
        let rx_ingress = ingress;
        let rx_task = tokio::spawn(async move {
            loop {
                if rx_probe.is_closed() {
                    break;
                }
                match rx_udp.recv_into_pool(&pool, DEFAULT_HEADROOM).await {
                    Ok((pkt, from)) if from == peer => {
                        rx_ingress.on_packet(
                            LinkMeta {
                                peer: l2_peer,
                                received_at_us: 0,
                                rssi_dbm: None,
                            },
                            pkt,
                        );
                    }
                    Ok((_, from)) => {
                        tracing::trace!(
                            link_id = id.0,
                            %from,
                            expected = %peer,
                            "ignoring UDP datagram from unexpected peer"
                        );
                    }
                    Err(err) if err.kind() == ErrorKind::OutOfMemory => {
                        tracing::debug!(
                            link_id = id.0,
                            "packet pool exhausted on UDP rx; backing off"
                        );
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                    Err(err)
                        if matches!(
                            err.kind(),
                            ErrorKind::WouldBlock
                                | ErrorKind::Interrupted
                                | ErrorKind::ConnectionRefused
                                | ErrorKind::ConnectionReset
                        ) =>
                    {
                        tracing::debug!(link_id = id.0, error = %err, "transient UDP rx error");
                    }
                    Err(err) => {
                        tracing::warn!(
                            link_id = id.0,
                            error = %err,
                            "UDP rx task exiting on fatal socket error"
                        );
                        break;
                    }
                }
            }
        });
        let _ = self.add_link_internal(
            id,
            l2_peer,
            profile,
            Box::new(UdpPacketLink {
                udp,
                peer,
                info: LinkInfo {
                    name: LinkName::new("udp").expect("static name"),
                    max_packet_size: DEFAULT_MAX_PAYLOAD,
                    prefix_required: 0,
                    suffix_required: 0,
                    requires_packet_encryption: false,
                    secure_link: false,
                    nominal_bitrate_bps: 0,
                    local_mac: None,
                },
            }),
            Some(rx_task),
        );
    }

    /// Spawn the association event loop and return `(mux_to_link_tx, link_to_mux_rx, task)`.
    pub fn spawn(
        self,
    ) -> (
        mpsc::Sender<Vec<u8>>,
        mpsc::Receiver<Vec<u8>>,
        JoinHandle<()>,
    ) {
        let cap = self.channel_capacity;
        let (mux_to_link_tx, mut mux_to_link_rx) = mpsc::channel::<Vec<u8>>(cap);
        let (link_to_mux_tx, link_to_mux_rx) = mpsc::channel::<Vec<u8>>(cap);
        let pool = self.pool;
        let assoc_config = self.assoc_config;
        let mut rx_rx = self.rx_rx;
        let tx_notify = self.tx_notify;
        let mut links: BTreeMap<LinkId, AttachedLink> =
            self.links.into_iter().map(|l| (l.id, l)).collect();

        let task = tokio::spawn(async move {
            let mut assoc = QuicLinkAssoc::<XipLazyPacket>::new(assoc_config);
            for link in links.values() {
                assoc.upsert_link(link.id, link.profile);
            }
            let start = Instant::now();
            let mut pending_mux_frame: Option<Vec<u8>> = None;
            let mut pending_to_mux: VecDeque<Vec<u8>> = VecDeque::new();
            let mut mux_closed = false;
            let mut to_mux_closed = false;
            let mut close_deadline: Option<Instant> = None;
            let mut retry_backoff_us = RETRY_MIN_BACKOFF_US;
            let mut next_retry_at: Option<Instant> = None;
            let mut force_poll_blocked = false;

            loop {
                let now_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                assoc.set_now_us(now_us);

                // Drain any pending mux frames one at a time while respecting association capacity.
                if let Some(raw) = pending_mux_frame.take() {
                    if let SubmitMuxOutcome::RetryLater(frame) =
                        submit_mux_frame(&pool, &mut assoc, raw)
                    {
                        pending_mux_frame = Some(frame);
                    }
                }
                if pending_mux_frame.is_none() && !mux_closed {
                    for _ in 0..MAX_TX_BATCH {
                        match mux_to_link_rx.try_recv() {
                            Ok(raw) => {
                                if let SubmitMuxOutcome::RetryLater(frame) =
                                    submit_mux_frame(&pool, &mut assoc, raw)
                                {
                                    pending_mux_frame = Some(frame);
                                    break;
                                }
                            }
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                mux_closed = true;
                                close_deadline
                                    .get_or_insert_with(|| Instant::now() + SHUTDOWN_FLUSH_TIMEOUT);
                                break;
                            }
                        }
                    }
                }

                let mut pool_clone = pool.clone();
                assoc.poll_timers(&mut pool_clone, now_us);

                // Drain newly generated outbound packets into each link's FIFO queue.
                while let Some(out) = assoc.pop_outbound_packet() {
                    if let Some(link) = links.get_mut(&out.link_id) {
                        link.pending_tx.push_back((out.packet_number, out.packet));
                    } else {
                        tracing::debug!(
                            link_id = out.link_id.0,
                            pn = out.packet_number,
                            "dropping outbound packet for unattached link"
                        );
                        let done_us =
                            u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                        assoc.on_driver_complete(
                            out.link_id,
                            out.packet_number,
                            LinkTxOutcome::Failed,
                            done_us,
                        );
                    }
                }

                // Flush queued packets per link. Blocked links are retried only when woken by
                // `tx_notify` or when their exponential backoff timer expires.
                let now_inst = Instant::now();
                let backoff_due = next_retry_at.is_some_and(|dl| now_inst >= dl);
                let poll_blocked = force_poll_blocked || backoff_due;
                force_poll_blocked = false;
                let mut made_tx_progress = false;
                let mut any_blocked = false;

                for link in links.values_mut() {
                    if link.pending_tx.is_empty() {
                        link.blocked = false;
                        if let Some(state) = assoc.link_mut(link.id) {
                            state.driver_ready = true;
                        }
                        continue;
                    }
                    if link.blocked && !poll_blocked {
                        any_blocked = true;
                        continue;
                    }
                    link.blocked = false;
                    while let Some((pn, pkt)) = link.pending_tx.pop_front() {
                        match link.driver.send_packet(link.peer, pkt) {
                            Ok(outcome) => {
                                made_tx_progress = true;
                                let done_us =
                                    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                                assoc.on_driver_complete(link.id, pn, outcome, done_us);
                            }
                            Err(pkt) => {
                                link.pending_tx.push_front((pn, pkt));
                                link.blocked = true;
                                any_blocked = true;
                                if let Some(state) = assoc.link_mut(link.id) {
                                    state.driver_ready = false;
                                }
                                break;
                            }
                        }
                    }
                    if link.pending_tx.is_empty() {
                        link.blocked = false;
                        if let Some(state) = assoc.link_mut(link.id) {
                            state.driver_ready = true;
                        }
                    }
                }

                if made_tx_progress {
                    retry_backoff_us = RETRY_MIN_BACKOFF_US;
                    next_retry_at = any_blocked
                        .then(|| Instant::now() + Duration::from_micros(retry_backoff_us));
                } else if any_blocked && (backoff_due || next_retry_at.is_none()) {
                    retry_backoff_us = (retry_backoff_us * 2).min(RETRY_MAX_BACKOFF_US);
                    next_retry_at = Some(Instant::now() + Duration::from_micros(retry_backoff_us));
                } else if !any_blocked {
                    retry_backoff_us = RETRY_MIN_BACKOFF_US;
                    next_retry_at = None;
                }

                // Try non-blocking flush of buffered RX frames toward `TokioMux`.
                while let Some(bytes) = pending_to_mux.pop_front() {
                    if to_mux_closed {
                        pending_to_mux.clear();
                        break;
                    }
                    match link_to_mux_tx.try_send(bytes) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(bytes)) => {
                            pending_to_mux.push_front(bytes);
                            break;
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            to_mux_closed = true;
                            pending_to_mux.clear();
                            break;
                        }
                    }
                }

                let assoc_drained = pending_mux_frame.is_none()
                    && (to_mux_closed || pending_to_mux.is_empty())
                    && links.values().all(|l| l.pending_tx.is_empty())
                    && assoc.outbound_queue_len() == 0
                    && assoc.pending_retransmits_len() == 0
                    && assoc.sack_ledger().retained_packets() == 0;
                if mux_closed {
                    if assoc_drained {
                        tracing::debug!("TokioAssocDriver clean shutdown complete");
                        return;
                    }
                    if close_deadline.is_some_and(|dl| Instant::now() >= dl) {
                        tracing::warn!(
                            inflight = assoc.sack_ledger().retained_packets(),
                            pending_retransmits = assoc.pending_retransmits_len(),
                            "TokioAssocDriver shutdown timeout with unacknowledged data"
                        );
                        return;
                    }
                }

                let now_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                let mut sleep_dur = match assoc.next_deadline_us() {
                    Some(dl) => Duration::from_micros(dl.saturating_sub(now_us).max(500)),
                    None if pending_mux_frame.is_some() => Duration::from_millis(2),
                    None => Duration::from_millis(25),
                };
                if let Some(retry_dl) = next_retry_at {
                    sleep_dur = sleep_dur.min(retry_dl.saturating_duration_since(Instant::now()));
                }
                if let Some(close_dl) = close_deadline {
                    sleep_dur = sleep_dur.min(close_dl.saturating_duration_since(Instant::now()));
                }
                let sleep_dur = if made_tx_progress && pending_mux_frame.is_some() {
                    Duration::ZERO
                } else {
                    sleep_dur.max(Duration::from_micros(200))
                };

                tokio::select! {
                    maybe_rx = rx_rx.recv(), if pending_to_mux.len() < cap => {
                        let Some((link_id, _meta, pkt)) = maybe_rx else {
                            continue;
                        };
                        handle_rx_packet(
                            &mut assoc,
                            link_id,
                            pkt,
                            &start,
                            &link_to_mux_tx,
                            &mut pending_to_mux,
                            &mut to_mux_closed,
                        );
                        let mut count = 1usize;
                        while count < MAX_RX_BATCH && pending_to_mux.len() < cap {
                            let Ok((link_id, _meta, pkt)) = rx_rx.try_recv() else {
                                break;
                            };
                            count += 1;
                            handle_rx_packet(
                                &mut assoc,
                                link_id,
                                pkt,
                                &start,
                                &link_to_mux_tx,
                                &mut pending_to_mux,
                                &mut to_mux_closed,
                            );
                        }
                    }
                    res = link_to_mux_tx.reserve(),
                        if !to_mux_closed && !pending_to_mux.is_empty() =>
                    {
                        match res {
                            Ok(permit) => {
                                if let Some(bytes) = pending_to_mux.pop_front() {
                                    permit.send(bytes);
                                }
                            }
                            Err(_) => {
                                to_mux_closed = true;
                                pending_to_mux.clear();
                            }
                        }
                    }
                    maybe_frame = mux_to_link_rx.recv(),
                        if !mux_closed && pending_mux_frame.is_none() =>
                    {
                        match maybe_frame {
                            Some(raw) => pending_mux_frame = Some(raw),
                            None => {
                                mux_closed = true;
                                close_deadline.get_or_insert_with(|| {
                                    Instant::now() + SHUTDOWN_FLUSH_TIMEOUT
                                });
                            }
                        }
                    }
                    _ = tx_notify.notified() => {
                        retry_backoff_us = RETRY_MIN_BACKOFF_US;
                        force_poll_blocked = true;
                    }
                    _ = tokio::time::sleep(sleep_dur) => {}
                }
            }
        });

        (mux_to_link_tx, link_to_mux_rx, task)
    }
}

enum SubmitMuxOutcome {
    Submitted,
    DroppedPermanent,
    RetryLater(Vec<u8>),
}

fn submit_mux_frame(
    pool: &XipLazyPool,
    assoc: &mut QuicLinkAssoc<XipLazyPacket>,
    raw: Vec<u8>,
) -> SubmitMuxOutcome {
    let Ok(mut pkt) = pool.alloc() else {
        tracing::debug!(
            frame_len = raw.len(),
            "packet pool exhausted submitting mux frame"
        );
        return SubmitMuxOutcome::RetryLater(raw);
    };
    if pkt.append(&raw).is_err() {
        tracing::warn!(
            frame_len = raw.len(),
            tailroom = pkt.tailroom(),
            "dropping mux frame that exceeds pool packet tailroom"
        );
        return SubmitMuxOutcome::DroppedPermanent;
    }
    let meta = TxPacketMeta {
        association: assoc.config().assoc_id,
        stream_id: None,
        priority: StreamPriority::NORMAL,
        retransmittable: true,
    };
    match assoc.send_packet(meta, pkt) {
        Ok(()) => SubmitMuxOutcome::Submitted,
        Err(LinkSendError::Busy(_)) => SubmitMuxOutcome::RetryLater(raw),
        Err(LinkSendError::TooLarge { max_frame_len, .. }) => {
            tracing::warn!(
                frame_len = raw.len(),
                max_frame_len,
                "dropping mux frame exceeding association MTU"
            );
            SubmitMuxOutcome::DroppedPermanent
        }
        Err(LinkSendError::NoAssociation(_)) => {
            tracing::error!(
                assoc_id = ?meta.association,
                "dropping mux frame for unknown association"
            );
            SubmitMuxOutcome::DroppedPermanent
        }
    }
}

fn handle_rx_packet(
    assoc: &mut QuicLinkAssoc<XipLazyPacket>,
    link_id: LinkId,
    pkt: XipLazyPacket,
    start: &Instant,
    link_to_mux_tx: &mpsc::Sender<Vec<u8>>,
    pending_to_mux: &mut VecDeque<Vec<u8>>,
    to_mux_closed: &mut bool,
) {
    let rx_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    match assoc.receive_packet(link_id, pkt, rx_us) {
        Ok(outcome) => {
            let Some(mux_pkt) = outcome.mux_packet else {
                return;
            };
            if *to_mux_closed {
                return;
            }
            let bytes = mux_pkt.bytes().to_vec();
            drop(mux_pkt);
            if pending_to_mux.is_empty() {
                match link_to_mux_tx.try_send(bytes) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(bytes)) => {
                        pending_to_mux.push_back(bytes);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        *to_mux_closed = true;
                    }
                }
            } else {
                pending_to_mux.push_back(bytes);
            }
        }
        Err(err) => {
            tracing::debug!(
                link_id = link_id.0,
                ?err,
                "failed to demux incoming link packet"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::vec;

    struct MockPacketLink {
        info: LinkInfo,
        blocked: Arc<AtomicBool>,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl PacketLink<XipLazyPacket> for MockPacketLink {
        fn info(&self) -> &LinkInfo {
            &self.info
        }

        fn send_packet(
            &mut self,
            _peer: PeerL2Address,
            packet: XipLazyPacket,
        ) -> Result<LinkTxOutcome, XipLazyPacket> {
            if self.blocked.load(Ordering::SeqCst) {
                return Err(packet);
            }
            self.sent.lock().unwrap().push(packet.bytes().to_vec());
            Ok(LinkTxOutcome::Sent)
        }
    }

    fn test_link_info() -> LinkInfo {
        LinkInfo {
            name: LinkName::new("mock").unwrap(),
            max_packet_size: DEFAULT_MAX_PAYLOAD,
            prefix_required: 0,
            suffix_required: 0,
            requires_packet_encryption: false,
            secure_link: false,
            nominal_bitrate_bps: 0,
            local_mac: None,
        }
    }

    #[tokio::test]
    async fn oversized_frame_is_dropped_without_stalling_subsequent_frames() {
        let mut driver = TokioAssocDriver::new(AssocConfig::default(), 16);
        let blocked = Arc::new(AtomicBool::new(false));
        let sent = Arc::new(Mutex::new(Vec::new()));
        driver.add_link(
            LinkId(1),
            PeerL2Address::new(1).unwrap(),
            LinkProfile::udp_datagram(1, 256, crate::ConnectionId::new(1).unwrap()),
            MockPacketLink {
                info: test_link_info(),
                blocked,
                sent: sent.clone(),
            },
        );
        let (tx, _rx, task) = driver.spawn();
        // Exceeds link MTU (256), triggers LinkSendError::TooLarge.
        tx.send(vec![0xaa; 512]).await.unwrap();
        // Valid subsequent frame must still be delivered promptly.
        tx.send(vec![0x11; 32]).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !sent.lock().unwrap().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("valid frame should not be stalled by prior oversized frame");

        task.abort();
    }

    #[tokio::test]
    async fn packets_behind_blocked_link_stay_queued_in_fifo_order() {
        let mut driver = TokioAssocDriver::new(AssocConfig::default(), 16);
        let blocked = Arc::new(AtomicBool::new(true));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let ingress = driver.add_link(
            LinkId(1),
            PeerL2Address::new(1).unwrap(),
            LinkProfile::udp_datagram(1, DEFAULT_MAX_PAYLOAD, crate::ConnectionId::new(1).unwrap()),
            MockPacketLink {
                info: test_link_info(),
                blocked: blocked.clone(),
                sent: sent.clone(),
            },
        );
        let (tx, _rx, task) = driver.spawn();

        for marker in [0xA1u8, 0xA2, 0xA3] {
            tx.send(vec![marker; 24]).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(sent.lock().unwrap().is_empty());

        blocked.store(false, Ordering::SeqCst);
        ingress.on_tx_ready();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if sent.lock().unwrap().len() >= 3 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("all queued packets should flush after link unblocks");

        let payloads = sent.lock().unwrap();
        assert_eq!(payloads.len(), 3);
        assert!(payloads[0].windows(24).any(|w| w == [0xA1; 24]));
        assert!(payloads[1].windows(24).any(|w| w == [0xA2; 24]));
        assert!(payloads[2].windows(24).any(|w| w == [0xA3; 24]));

        drop(tx);
        task.abort();
    }
}
