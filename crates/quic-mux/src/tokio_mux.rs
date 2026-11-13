//! Standalone `std`/`tokio` transport adapter for `quic-mux` over TCP (`TcpStream`) and
//! Unix Domain Sockets (`UnixStream` framed streams and `UnixDatagram` packet sockets).
//!
//! Supports both single-link and multi-link (e.g., 2..3 mixed TCP + UDS links per association)
//! operation with zero-copy pool headroom framing and TX small-packet coalescing:
//! - **TX:** `quic-mux` writes the `STREAM` header in pool headroom (`< 144`). Whenever a link
//!   already has pending packets in its TX ring, incoming small packets (`<= mtu / 3`) for the
//!   same association are combined in-place into the tail pending packet via
//!   [`crate::link::try_coalesce_tx_packet`], immediately freeing the absorbed pool slot.
//!   The link writer then prepends a 4-byte `[u16be assoc_id, u16be frame_len]` header (or 2-byte
//!   `[u16be assoc_id]` on datagram sockets) in-place in front of `packet.range().start` and
//!   writes the slice directly to the kernel socket with zero payload copies.
//! - **RX:** The link allocates a `XipLazyPacket` from the shared pool, reads the frame payload
//!   directly into the slot at `headroom..headroom + frame_len`, and passes ownership of the
//!   `XipLazyPacket` to `QuicMux::receive_packet`.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::sync::{Arc, Mutex};
use std::vec::Vec;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpStream, UnixDatagram, UnixStream};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

use crate::link::{
    AssociationEgress, AssociationId, LinkSendError, TxPacketMeta, default_coalesce_threshold,
    try_coalesce_tx_packet,
};
use crate::pool::{PacketPool, PoolPacket, XipLazyPacket, XipLazyPool};

pub use crate::tokio_stream::{
    MuxReadHalf, MuxStream, MuxWriteHalf, OwnedRxChunk, TokioMux, TokioMuxAcceptor, TokioMuxConfig,
};

/// One inbound packet received from a TCP or UDS link.
pub struct TokioRxPacket {
    /// Association decoded from the link frame header.
    pub association: AssociationId,
    /// Pool packet lease with `range()` set to the `quic-mux` frame.
    pub packet: XipLazyPacket,
}

struct LinkTxRingInner {
    queue: VecDeque<(TxPacketMeta, XipLazyPacket)>,
    writing_bytes: bool,
    closed: bool,
    coalesced_packets: u64,
}

struct LinkTxRing {
    mtu: usize,
    coalesce_threshold: usize,
    capacity: usize,
    inner: Mutex<LinkTxRingInner>,
    has_pkt_notify: Notify,
    space_notify: Arc<Notify>,
}

impl LinkTxRing {
    fn new(mtu: usize, capacity: usize, space_notify: Arc<Notify>) -> Arc<Self> {
        Arc::new(Self {
            mtu,
            coalesce_threshold: default_coalesce_threshold(mtu),
            capacity: capacity.max(1),
            inner: Mutex::new(LinkTxRingInner {
                queue: VecDeque::with_capacity(capacity.max(1)),
                writing_bytes: false,
                closed: false,
                coalesced_packets: 0,
            }),
            has_pkt_notify: Notify::new(),
            space_notify,
        })
    }

    fn has_space(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        !inner.closed && inner.queue.len() < self.capacity
    }

    fn is_flushed(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.closed || (inner.queue.is_empty() && !inner.writing_bytes)
    }

    fn is_closed(&self) -> bool {
        self.inner.lock().unwrap().closed
    }

    fn coalesced_count(&self) -> u64 {
        self.inner.lock().unwrap().coalesced_packets
    }

    fn close(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.closed = true;
        inner.writing_bytes = false;
        inner.queue.clear();
        drop(inner);
        self.has_pkt_notify.notify_waiters();
        self.space_notify.notify_waiters();
    }

    fn try_enqueue(&self, meta: TxPacketMeta, pkt: XipLazyPacket) -> Result<(), XipLazyPacket> {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            return Err(pkt);
        }
        // Coalesce small packets (`<= mtu / 3`) when the link already has pending packets queued.
        let pkt = if let Some((tail_meta, tail_pkt)) = inner.queue.back_mut() {
            match try_coalesce_tx_packet(
                tail_meta,
                tail_pkt,
                meta,
                pkt,
                self.mtu,
                self.coalesce_threshold,
            ) {
                Ok(()) => {
                    inner.coalesced_packets += 1;
                    return Ok(());
                }
                Err(returned) => returned,
            }
        } else {
            pkt
        };

        if inner.queue.len() >= self.capacity {
            return Err(pkt);
        }
        let was_empty = inner.queue.is_empty();
        inner.queue.push_back((meta, pkt));
        drop(inner);
        if was_empty {
            self.has_pkt_notify.notify_one();
        }
        Ok(())
    }

    fn try_pop(&self) -> Option<(TxPacketMeta, XipLazyPacket)> {
        self.inner.lock().unwrap().queue.pop_front()
    }

    fn mark_flush_complete(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.queue.is_empty() {
            inner.writing_bytes = false;
        }
        drop(inner);
        self.space_notify.notify_waiters();
    }

    async fn pop_or_wait(&self) -> Option<(TxPacketMeta, XipLazyPacket)> {
        loop {
            let notified = self.has_pkt_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut inner = self.inner.lock().unwrap();
                if let Some((meta, pkt)) = inner.queue.pop_front() {
                    inner.writing_bytes = true;
                    return Some((meta, pkt));
                }
                inner.writing_bytes = false;
                if inner.closed {
                    return None;
                }
            }
            notified.await;
        }
    }
}

struct AttachedLink {
    cost: u16,
    mtu: usize,
    ring: Arc<LinkTxRing>,
    reader_task: JoinHandle<io::Result<()>>,
    writer_task: JoinHandle<io::Result<()>>,
}

impl Drop for AttachedLink {
    fn drop(&mut self) {
        self.ring.close();
        self.reader_task.abort();
        self.writer_task.abort();
    }
}

/// Multi-link `tokio` egress and ingress router implementing [`AssociationEgress<XipLazyPacket>`].
///
/// An association can attach one or multiple TCP (`TcpStream`) and UDS (`UnixStream` / `UnixDatagram`)
/// links with per-link costs. Outgoing packets are offered in cost order (round-robining across
/// equal-cost links for multipath striping, coalescing small `< 1/3 MTU` packets when a link has
/// pending packets, and failing over immediately when a link's fixed-capacity ring is full).
pub struct TokioLinkSet {
    pool: XipLazyPool,
    rx_tx: mpsc::Sender<TokioRxPacket>,
    rx_rx: Option<mpsc::Receiver<TokioRxPacket>>,
    tx_space_notify: Arc<Notify>,
    links: BTreeMap<AssociationId, Vec<AttachedLink>>,
    rr_cursor: BTreeMap<AssociationId, usize>,
    had_links: bool,
}

impl TokioLinkSet {
    /// Create a new `TokioLinkSet` backed by `pool` with an inbound channel capacity of `rx_capacity`.
    pub fn new(pool: XipLazyPool, rx_capacity: usize) -> Self {
        let (rx_tx, rx_rx) = mpsc::channel(rx_capacity.max(1));
        Self {
            pool,
            rx_tx,
            rx_rx: Some(rx_rx),
            tx_space_notify: Arc::new(Notify::new()),
            links: BTreeMap::new(),
            rr_cursor: BTreeMap::new(),
            had_links: false,
        }
    }

    /// Take the inbound packet receiver (`mpsc::Receiver<TokioRxPacket>`) so an async driver loop
    /// can await inbound packets without holding a lock on `TokioLinkSet`.
    pub fn take_rx_receiver(&mut self) -> Option<mpsc::Receiver<TokioRxPacket>> {
        self.rx_rx.take()
    }

    /// Shared `Notify` signaled whenever link TX ring space opens up.
    #[inline]
    pub fn tx_space_notify(&self) -> Arc<Notify> {
        self.tx_space_notify.clone()
    }

    /// Whether all queued packets on all links for `assoc` have been written and flushed to the OS.
    pub fn is_assoc_flushed(&self, assoc: AssociationId) -> bool {
        let Some(list) = self.links.get(&assoc).or_else(|| self.links.get(&AssociationId(1)))
        else {
            return true;
        };
        list.iter().all(|l| l.ring.is_flushed())
    }

    /// Whether at least one link has been attached to this link set.
    pub fn has_links(&self) -> bool {
        self.had_links
    }

    /// Whether at least one link was attached and every attached link has closed (EOF or error).
    pub fn all_links_closed(&self) -> bool {
        self.had_links
            && self
                .links
                .values()
                .flat_map(|v| v.iter())
                .all(|l| l.ring.is_closed())
    }

    /// Close and detach all links across all associations, aborting their I/O tasks.
    pub fn close_all(&mut self) {
        self.links.clear();
        self.rr_cursor.clear();
        self.tx_space_notify.notify_waiters();
    }

    /// Total number of small TX packets (`<= mtu / 3`) coalesced into pending packets across all links.
    pub fn coalesced_tx_packets(&self) -> u64 {
        self.links
            .values()
            .flat_map(|v| v.iter())
            .map(|l| l.ring.coalesced_count())
            .sum()
    }

    /// Attach a `TcpStream` link to `assoc`.
    pub fn add_tcp_link(
        &mut self,
        assoc: AssociationId,
        stream: TcpStream,
        cost: u16,
        tx_ring_capacity: usize,
    ) {
        let _ = stream.set_nodelay(true);
        self.add_stream_link(assoc, stream, cost, tx_ring_capacity);
    }

    /// Attach a `UnixStream` link to `assoc`.
    pub fn add_uds_stream_link(
        &mut self,
        assoc: AssociationId,
        stream: UnixStream,
        cost: u16,
        tx_ring_capacity: usize,
    ) {
        self.add_stream_link(assoc, stream, cost, tx_ring_capacity);
    }

    /// Attach any byte-stream link (`TcpStream`, `UnixStream`, TLS stream, etc.) to `assoc`.
    ///
    /// Frames raw self-delimiting QUIC frames directly on the stream (`STREAM` frames with the
    /// `0x02` `LEN` bit + control frames, with no outer packet wrapper).
    pub fn add_stream_link<S>(
        &mut self,
        assoc: AssociationId,
        stream: S,
        cost: u16,
        tx_ring_capacity: usize,
    ) where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (rd, wr) = tokio::io::split(stream);
        let mut rd = BufReader::with_capacity(64 * 1024, rd);
        let mut wr = BufWriter::with_capacity(64 * 1024, wr);
        let headroom_slack = self.pool.headroom().min(32);
        let mtu = self.pool.max_payload() + headroom_slack;
        let ring = LinkTxRing::new(mtu, tx_ring_capacity, self.tx_space_notify.clone());
        let ring_wr = ring.clone();

        let writer_task = tokio::spawn(async move {
            let res: io::Result<()> = async {
                while let Some((_meta, mut pkt)) = ring_wr.pop_or_wait().await {
                    loop {
                        wr.write_all(pkt.bytes()).await?;
                        drop(pkt);
                        ring_wr.space_notify.notify_waiters();
                        match ring_wr.try_pop() {
                            Some((_next_meta, next_pkt)) => {
                                pkt = next_pkt;
                            }
                            None => break,
                        }
                    }
                    wr.flush().await?;
                    ring_wr.mark_flush_complete();
                }
                Ok(())
            }
            .await;
            ring_wr.close();
            res
        });

        let pool_rd = self.pool.clone();
        let rx_tx = self.rx_tx.clone();
        let notify_rd = self.tx_space_notify.clone();
        let ring_rd = ring.clone();
        let reader_task = tokio::spawn(async move {
            let res: io::Result<()> = async {
                let headroom = pool_rd.headroom();
                let slot_cap = headroom + pool_rd.max_payload();
                let max_frame = pool_rd.max_payload() + headroom.min(32);
                let mut peek = [0u8; crate::wire::MAX_STREAM_FRAME_HEADER_LEN];
                let mut peek_len = 0usize;

                loop {
                    let total_len = loop {
                        match crate::wire::plan_stream_packet(&peek[..peek_len], max_frame) {
                            Ok(crate::wire::StreamPacketPlan::Ready { total_len }) => {
                                break total_len;
                            }
                            Ok(crate::wire::StreamPacketPlan::NeedMoreHeader) => {
                                let n = rd.read(&mut peek[peek_len..]).await?;
                                if n == 0 {
                                    if peek_len == 0 {
                                        return Ok(());
                                    }
                                    return Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "truncated quic-mux frame header on stream",
                                    ));
                                }
                                peek_len += n;
                            }
                            Err(_) => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid quic-mux frame header on stream",
                                ));
                            }
                        }
                    };
                    if total_len > slot_cap {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "incoming frame exceeds slot capacity",
                        ));
                    }
                    let mut pkt = loop {
                        match pool_rd.alloc() {
                            Ok(p) => break p,
                            Err(_) => {
                                tokio::task::yield_now().await;
                            }
                        }
                    };
                    // Place the `quic-mux` frame starting at `headroom - 8` (or lower inside
                    // headroom for coalesced frames > `max_payload + 8`) so the slot never overflows
                    // and payload bytes land near `headroom` after stripping the `STREAM` header.
                    let rx_start = (slot_cap - total_len).min(headroom.saturating_sub(8));
                    let take = total_len.min(peek_len);
                    {
                        let slot = pkt.slot_slice_mut().map_err(|_| {
                            io::Error::new(io::ErrorKind::Other, "fresh pool packet not unique")
                        })?;
                        slot[rx_start..rx_start + take].copy_from_slice(&peek[..take]);
                        if take < peek_len {
                            peek.copy_within(take..peek_len, 0);
                        }
                        peek_len -= take;
                        if take < total_len {
                            rd.read_exact(&mut slot[rx_start + take..rx_start + total_len])
                                .await?;
                        }
                    }
                    pkt.set_range(rx_start..rx_start + total_len).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid range")
                    })?;
                    if rx_tx
                        .send(TokioRxPacket {
                            association: assoc,
                            packet: pkt,
                        })
                        .await
                        .is_err()
                    {
                        return Ok(());
                    }
                    notify_rd.notify_waiters();
                }
            }
            .await;
            ring_rd.close();
            res
        });

        self.had_links = true;
        let list = self.links.entry(assoc).or_default();
        list.push(AttachedLink {
            cost,
            mtu,
            ring,
            reader_task,
            writer_task,
        });
        list.sort_by_key(|l| l.cost);
    }

    /// Attach a connected `UnixDatagram` packet link to `assoc`.
    ///
    /// Each datagram carries a raw `quic-mux` packet directly.
    pub fn add_datagram_link(
        &mut self,
        assoc: AssociationId,
        dgram: UnixDatagram,
        cost: u16,
        tx_ring_capacity: usize,
    ) {
        let dgram = Arc::new(dgram);
        let dgram_wr = dgram.clone();
        let headroom_slack = self.pool.headroom().min(32);
        let mtu = self.pool.max_payload() + headroom_slack;
        let ring = LinkTxRing::new(mtu, tx_ring_capacity, self.tx_space_notify.clone());
        let ring_wr = ring.clone();

        let writer_task = tokio::spawn(async move {
            let res: io::Result<()> = async {
                while let Some((_meta, pkt)) = ring_wr.pop_or_wait().await {
                    dgram_wr.send(pkt.bytes()).await?;
                    drop(pkt);
                    ring_wr.space_notify.notify_waiters();
                    ring_wr.mark_flush_complete();
                }
                Ok(())
            }
            .await;
            ring_wr.close();
            res
        });

        let pool_rd = self.pool.clone();
        let rx_tx = self.rx_tx.clone();
        let notify_rd = self.tx_space_notify.clone();
        let ring_rd = ring.clone();
        let reader_task = tokio::spawn(async move {
            let res: io::Result<()> = async {
                loop {
                    dgram.readable().await?;
                    let mut pkt = loop {
                        match pool_rd.alloc() {
                            Ok(p) => break p,
                            Err(_) => tokio::task::yield_now().await,
                        }
                    };
                    let headroom = pool_rd.headroom();
                    let rx_start = headroom.saturating_sub(32);
                    let n = {
                        let slot = pkt.slot_slice_mut().map_err(|_| {
                            io::Error::new(io::ErrorKind::Other, "fresh pool packet not unique")
                        })?;
                        let slot_end = slot.len();
                        match dgram.try_recv(&mut slot[rx_start..slot_end]) {
                            Ok(n) => n,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                            Err(e) => return Err(e),
                        }
                    };
                    if n == 0 {
                        continue;
                    }
                    pkt.set_range(rx_start..(rx_start + n)).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid range")
                    })?;
                    if rx_tx
                        .send(TokioRxPacket {
                            association: assoc,
                            packet: pkt,
                        })
                        .await
                        .is_err()
                    {
                        return Ok(());
                    }
                    notify_rd.notify_waiters();
                }
            }
            .await;
            ring_rd.close();
            res
        });

        self.had_links = true;
        let list = self.links.entry(assoc).or_default();
        list.push(AttachedLink {
            cost,
            mtu,
            ring,
            reader_task,
            writer_task,
        });
        list.sort_by_key(|l| l.cost);
    }

    /// Attach a packet-oriented channel link (such as PPP serial port `245` or BLE CoC) to `assoc`.
    ///
    /// Each packet is a raw `quic-mux` packet up to `mtu` bytes (`mtu` is capped to `pool.max_payload() + 32`).
    pub fn add_packet_link(
        &mut self,
        assoc: AssociationId,
        tx: mpsc::Sender<Vec<u8>>,
        mut rx: mpsc::Receiver<Vec<u8>>,
        mtu: usize,
        cost: u16,
        tx_ring_capacity: usize,
    ) {
        let headroom_slack = self.pool.headroom().min(32);
        let max_frame = self.pool.max_payload() + headroom_slack;
        let mtu = mtu.clamp(64, max_frame);
        let ring = LinkTxRing::new(mtu, tx_ring_capacity, self.tx_space_notify.clone());
        let ring_wr = ring.clone();

        let writer_task = tokio::spawn(async move {
            let res: io::Result<()> = async {
                while let Some((_meta, pkt)) = ring_wr.pop_or_wait().await {
                    let wire = pkt.bytes().to_vec();
                    drop(pkt);
                    tx.send(wire).await.map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "packet link TX closed")
                    })?;
                    ring_wr.space_notify.notify_waiters();
                    ring_wr.mark_flush_complete();
                }
                Ok(())
            }
            .await;
            ring_wr.close();
            res
        });

        let pool_rd = self.pool.clone();
        let rx_tx = self.rx_tx.clone();
        let notify_rd = self.tx_space_notify.clone();
        let ring_rd = ring.clone();
        let reader_task = tokio::spawn(async move {
            let res: io::Result<()> = async {
                while let Some(raw) = rx.recv().await {
                    if raw.is_empty() || raw.len() > max_frame {
                        continue;
                    }
                    let mut pkt = loop {
                        match pool_rd.alloc() {
                            Ok(p) => break p,
                            Err(_) => tokio::task::yield_now().await,
                        }
                    };
                    let headroom = pool_rd.headroom();
                    let slot_cap = headroom + pool_rd.max_payload();
                    let rx_start = (slot_cap - raw.len()).min(headroom.saturating_sub(8));
                    {
                        let slot = pkt.slot_slice_mut().map_err(|_| {
                            io::Error::new(io::ErrorKind::Other, "fresh pool packet not unique")
                        })?;
                        slot[rx_start..rx_start + raw.len()].copy_from_slice(&raw);
                    }
                    pkt.set_range(rx_start..rx_start + raw.len()).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid range")
                    })?;
                    if rx_tx
                        .send(TokioRxPacket {
                            association: assoc,
                            packet: pkt,
                        })
                        .await
                        .is_err()
                    {
                        return Ok(());
                    }
                    notify_rd.notify_waiters();
                }
                Ok(())
            }
            .await;
            ring_rd.close();
            res
        });

        self.had_links = true;
        let list = self.links.entry(assoc).or_default();
        list.push(AttachedLink {
            cost,
            mtu,
            ring,
            reader_task,
            writer_task,
        });
        list.sort_by_key(|l| l.cost);
    }

    /// Receive the next inbound packet from any attached TCP or UDS link.
    pub async fn recv_packet(&mut self) -> Option<TokioRxPacket> {
        match &mut self.rx_rx {
            Some(rx) => rx.recv().await,
            None => None,
        }
    }

    /// Try to receive an inbound packet without awaiting.
    pub fn try_recv_packet(&mut self) -> Option<TokioRxPacket> {
        self.rx_rx.as_mut()?.try_recv().ok()
    }

    /// Wait until TX ring space or a new RX packet becomes available.
    pub async fn wait_progress(&self) {
        self.tx_space_notify.notified().await;
    }
}

impl AssociationEgress<XipLazyPacket> for TokioLinkSet {
    fn max_writable_frame_len(&self, assoc: AssociationId) -> usize {
        let Some(list) = self.links.get(&assoc) else {
            return 0;
        };
        if !list.iter().any(|l| l.ring.has_space()) {
            return 0;
        }
        // Cap built frames to the smallest open link MTU on this association so multipath
        // failover (e.g. TCP 1532 + PPP serial 1498) never creates a frame that a backup link
        // cannot transmit.
        list.iter()
            .filter(|l| !l.ring.is_closed())
            .map(|l| l.mtu)
            .min()
            .unwrap_or(0)
    }

    fn send_packet(
        &mut self,
        meta: TxPacketMeta,
        packet: XipLazyPacket,
    ) -> Result<(), LinkSendError<XipLazyPacket>> {
        let link_key = meta.association;
        let Some(list) = self.links.get(&link_key) else {
            return Err(LinkSendError::NoAssociation(packet));
        };
        if list.is_empty() {
            return Err(LinkSendError::NoAssociation(packet));
        }

        let n = list.len();
        let start = *self.rr_cursor.get(&link_key).unwrap_or(&0) % n;
        let mut pkt = packet;

        // First pass: try lowest-cost links in round-robin order; second pass: higher-cost failover links.
        let min_cost = list[0].cost;
        for pass in 0..2 {
            for offset in 0..n {
                let idx = (start + offset) % n;
                let link = &list[idx];
                if (pass == 0 && link.cost != min_cost) || (pass == 1 && link.cost == min_cost) {
                    continue;
                }
                if pkt.bytes().len() > link.mtu {
                    continue;
                }
                match link.ring.try_enqueue(meta, pkt) {
                    Ok(()) => {
                        self.rr_cursor.insert(link_key, (idx + 1) % n);
                        return Ok(());
                    }
                    Err(returned) => {
                        pkt = returned;
                    }
                }
            }
        }
        Err(LinkSendError::Busy(pkt))
    }
}
