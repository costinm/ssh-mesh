# `quic-mux`

`quic-mux` is a `#![no_std]` (with optional `std` and `tokio` support) stream multiplexer and 3-tier flow-control engine built on RFC 9000 QUIC `STREAM` and flow-control frames.

It is designed as a lightweight, zero-copy alternative to single-stream multiplexers such as **Yamux**, **Smux**, or **OpenSSH ControlMaster mux**, works over both stream transports (**TCP**, **TLS**, **UDS stream**, **UART**, **USB**, **BLE CoC**) and packet/datagram transports (**UDS datagram**, **UDP**, **ESP-NOW**, **NAN**, **LoRa**), and supports **multipath striping and failover across multiple links simultaneously**.

---

## Why Use `quic-mux` Instead of Yamux or SSH Mux?

| Feature | Yamux / Smux / SSH Mux | `quic-mux` |
|---|---|---|
| **Underlying Links per Session** | Bound to **1 ordered byte stream** (a single TCP or UDS socket). Cannot stripe or fail over across links because frames have no stream byte offset. | **1 to $N$ heterogeneous links per association** (e.g., 2 TCP streams + 1 UDS socket, or UART + TCP + UDP). Every `STREAM` frame carries an explicit byte `offset`, so packets arriving out of order across links are reassembled per stream. |
| **Buffer & Memory Model** | Typically allocates a new `Vec<u8>` per frame or copies between stream rings and socket buffers. | **Zero-copy prefix headroom (`PoolPacket`)**: payload is written once at `headroom` (`144` bytes). `quic-mux` and link layers prepend headers in-place in front of the payload. |
| **Proxy / Gateway Forwarding** | Copy-in from ingress stream, re-frame, copy-out to egress stream. | **Zero-copy ownership handoff**: on single-stream packets (and on multi-frame packets with a `> 1/2 MTU` frame after copying smaller frames out), `quic-mux` hands the owned `PoolPacket` (`refs == 1`) to the stream handler or `MuxStream::recv_chunk`. A proxy handler can forward that exact `PoolPacket` on another stream with zero copies. |
| **Small-Write Coalescing** | Either Nagle delay or 1 frame header + syscall per small write. | **Zero-delay TX coalescing (`<= 1/3 MTU`)**: when a link already has pending packets queued, small packets (`<= mtu / 3`) for the same association are merged in-place into the tail pending packet via `try_coalesce_tx_packet`, immediately freeing the absorbed pool slot. |
| **User-Facing Async API** | Byte stream (`AsyncRead + AsyncWrite`) only. | **Dual `tokio` API on [`MuxStream`](src/tokio_stream.rs)**: drop-in TCP substitute (`AsyncRead + AsyncWrite`, `into_split()`, `TokioMuxAcceptor::accept()`) **plus** zero-copy packet pool ownership passing (`alloc_packet`, `send_packet`, `recv_chunk` -> `OwnedRxChunk`), mixable on the same stream. |
| **Link Reliability Assumption** | Assumes the underlying TCP/UDS socket is infallibly reliable until EOF. | **Zero-trust middle links**: `QuicMux` tracks out-of-order gaps with `gap_timeout_us` (emitting `RESET_STREAM` / `STOP_SENDING` to the peer and `on_association_broken` if a middle frame never arrives), and `link::SackRetransmitLedger` provides a standalone SACK/retransmit building block for unreliable-link connection layers (`TokioLinkSet` itself runs directly over stream/datagram sockets without SACK framing). |
| **Memory Pressure & Overload** | Fixed per-stream window; idle or stalled streams can pin memory until connection drop. | **Stream priorities (`CRITICAL`..`BULK`) + dynamic limits**: `QuicMux` enforces runtime-adjustable device, association, and per-stream RX packet limits (evicting/`RST`-ing the lowest-priority streams first and reclaiming `MAX_DATA` credit), and `SackRetransmitLedger` provides matching priority eviction for retained TX packets. |
| **Environment Support** | `std` + async runtime required. | **`#![no_std]` core by default (`default = []`)** + opt-in `features = ["tokio"]` adapter (`TokioMux`, `MuxStream`, `TokioLinkSet`) for `TcpStream`, `UnixStream`, and `UnixDatagram`. |

---

## Core Concepts

### 1. Zero-Copy Pool Headroom Layout
Packets allocated from a [`PacketPool`](src/pool.rs) reserve prefix headroom (`DEFAULT_HEADROOM = 144` bytes, matching `XIP_PKT_HEADROOM`):

```text
┌──────────────────────┬──────────────────────┬──────────────────────────┬──────────┐
│ 0 .. 112             │ 112 .. 144           │ 144 .. 144 + payload_len │ .. 1704  │
│ Link / Conn Header   │ STREAM Hdr (+ CTRL)  │ Stream Payload           │ Tail     │
│ (TCP/UDS/QUIC short) │ (quic-mux: 3..32B)   │ (Application / Proxy)    │          │
└──────────────────────┴──────────────────────┴──────────────────────────┴──────────┘
```

1. **Send (`write_stream`):** The application writes payload bytes at `144..144 + len` and passes `TxStreamData::Packet(pkt)` (or passes a small non-pool slice `TxStreamData::Bytes(&[u8])`). `quic-mux` encodes any pending `MAX_DATA` / `MAX_STREAM_DATA` updates and the `STREAM` header directly in front of byte `144` in-place.
2. **Link Egress (`AssociationEgress::send_packet`):** `quic-mux` transfers ownership of `pkt` + [`TxPacketMeta`](src/link.rs) (`association`, `stream_id`, `priority`, `retransmittable`) to the link/association layer, which selects the link in cost order and prepends its link header in front of the `quic-mux` header. If all links refuse with `Busy`, `quic-mux` restores `pkt.range()` to `144..144 + len` and returns `pkt` to the caller with no queue.
3. **Receive & Proxy Forwarding (`receive_packet`):**
   - **Packet-Atomic Validation & Exact Wire Order:** `receive_packet` validates every frame in the packet before mutating state (a malformed trailing frame discards the entire packet atomically) and then executes control frames and `STREAM` frames in **exact wire order** without per-packet `Vec` heap allocations on the hot path.
   - **Zero-Copy Single-Stream & `> 1/2 MTU` Ownership Split:** On a single-stream packet, `quic-mux` strips the `STREAM` header by advancing `pkt.range().start` back to `144` and passes exclusive ownership of `pkt` (`RxStreamChunk { packet: Some(pkt), small_buf: &[] }`) to `MuxCallbacks::on_stream_data`. When a link has pending TX packets, small packets (`<= mtu / 3`) for the same association can be appended into the tail pending packet (`try_coalesce_tx_packet`), freeing the absorbed pool slot immediately. On RX of a multi-frame packet, if a `STREAM` frame is `> 1/2 MTU` (at most one frame in an MTU packet can exceed `1/2 MTU`), `quic-mux` executes earlier frames from borrowed slices, copies any trailing (`<= 1/2 MTU`) frames onto a stack buffer so `pkt.is_unique()` stays `true`, transfers exclusive `PoolPacket` ownership for the `> 1/2 MTU` frame, and then executes the trailing frames.

### 2. Built-In Packet Pools (`pool.rs`)
`quic-mux` includes three thread-safe (`Send + Sync`) implementations of [`PacketPool`](src/pool.rs) whose packet leases (`StaticPacketLease`, `HeapPacketLease`, `XipLazyPacket`) are `Send + !Sync` with saturating atomic refcounts to guarantee alias-free in-place mutation when `is_unique()`:
- **[`XipLazyPool`](src/pool.rs) (aliased as `SlabPool`):** Replicates the ESP-XIP C runtime pool (`xip_pool.c`). Uses two-pass acquisition (claiming warm cached buffers on pass 0 before allocating on pass 1), retains `keep` (default `2`) warm idle buffers on release while immediately freeing excess buffers above `keep`, and supports `prepare_rx()`, `trim()`, and 16-bit generation-checked handles.
- **[`StaticPacketPool<SLOTS, MTU>`](src/pool.rs):** Fixed-capacity inline `[[u8; MTU]; SLOTS]` array (`SLOTS <= 32`) with lock-free `AtomicU32` availability bitmap and `AtomicU8` reference counts for zero-heap `#![no_std]` targets.
- **[`HeapPacketPool<MAX_SLOTS, MTU>`](src/pool.rs):** Dynamically resizable slot table with custom allocator callbacks (`HeapPacketAllocator`), RAM reserve budgeting (`resize_with_budget`, `maintain_free`), and non-spinning callback retirement.

### 3. Three-Tier Flow Control & Priority Eviction
- **Tier 1 — Global Device Capacity (`set_device_capacity`, `set_device_rx_packet_limit`):** Throttles outgoing writes and pauses automatic receive-window slides when the device is overloaded.
- **Tier 2 — Association Window (`MAX_DATA`, `MAX_STREAMS`, `set_association_limits`):** Connection-wide byte and packet limits.
- **Tier 3 — Stream Window (`MAX_STREAM_DATA`, `stream_send_capacity`, `RxOutcome::RetainedPendingCredit`):** Per-stream credit tracking. Proxy handlers can return `RxOutcome::RetainedPendingCredit` and call `release_stream_credit` only after downstream forwarding completes.
- **Priority Eviction (`StreamPriority`):** Streams are tagged with `StreamPriority` (`CRITICAL = 0`, `HIGH = 64`, `NORMAL = 128`, `LOW = 192`, `BULK = 255`). When RX out-of-order queues or the TX [`SackRetransmitLedger`](src/link.rs) hit their dynamic limits under load, the lowest-priority stream is automatically reset (`StreamCloseReason::ResourcePressure`) and its pool packets are reclaimed.

---

## Quick Start

By default, `quic-mux` has **no enabled features (`default = []`)** so embedded `#![no_std]` crates only pull in `core` + `alloc`. Enable `features = ["tokio"]` in `Cargo.toml` to use `TokioMux`, `MuxStream`, and `tokio_mux::TokioLinkSet`:
```toml
[dependencies]
# Async Tokio API (`TokioMux`, `MuxStream`, `TokioLinkSet`):
quic-mux = { path = "../quic-mux", features = ["tokio"] }

# Or pure `#![no_std]` core (`QuicMux`, `PacketPool`, `SackRetransmitLedger`):
# quic-mux = { path = "../quic-mux", default-features = false }
```

### 1. Drop-In TCP Substitute (`TokioMux` + `MuxStream` `AsyncRead + AsyncWrite`)

`TokioMux` and `TokioMuxAcceptor` mirror `TcpStream::connect` and `TcpListener::accept` over one or multiple TCP/UDS links:

```rust,ignore
use quic_mux::{TokioMux, TokioMuxConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Attach one or multiple links (multipath striping + failover across TCP and UDS!)
let (client_mux, _client_acceptor) = TokioMux::spawn(true, TokioMuxConfig::default());
client_mux.add_tcp_link(tcp_client, 10);
client_mux.add_uds_stream_link(uds_client, 10);

let (server_mux, mut server_acceptor) = TokioMux::spawn(false, TokioMuxConfig::default());
server_mux.add_tcp_link(tcp_server, 10);
server_mux.add_uds_stream_link(uds_server, 10);

// Server task: identical to a `TcpListener` echo loop
tokio::spawn(async move {
    while let Some(stream) = server_acceptor.accept().await {
        tokio::spawn(async move {
            let (mut rd, mut wr) = stream.into_split();
            tokio::io::copy(&mut rd, &mut wr).await.unwrap();
            wr.shutdown().await.unwrap();
        });
    }
});

// Client task: `MuxStream` implements `tokio::io::AsyncRead + AsyncWrite + Unpin`
let mut stream = client_mux.open_bidi().await.unwrap();
stream.write_all(b"hello over multipath quic-mux").await.unwrap();
stream.shutdown().await.unwrap();

let mut reply = Vec::new();
stream.read_to_end(&mut reply).await.unwrap();
```

### 2. Zero-Copy Packet Ownership Passing & Hybrid Splicing (`MuxStream`)

The same `MuxStream` (and `MuxReadHalf` / `MuxWriteHalf`) exposes `alloc_packet()`, `alloc_packet_async()`, `send_in_place(fin, populate)`, `send_packet(pkt, fin)`, `recv_chunk() -> OwnedRxChunk`, and `recv_chunks_drained(on_chunk)`. You can even read a routing header via `AsyncReadExt::read_exact` and splice the rest of the stream zero-copy:

```rust,ignore
use quic_mux::{PoolPacket, TokioMux};
use tokio::io::AsyncReadExt;

// Read an 8-byte routing header using standard `AsyncRead`, then forward all remaining
// packets zero-copy onto an outbound `TokioMux` stream!
let mut route_hdr = [0u8; 8];
inbound_stream.read_exact(&mut route_hdr).await?;

let mut outbound_stream = backend_mux.open_bidi().await?;
while let Some(mut chunk) = inbound_stream.recv_chunk().await? {
    let fin = chunk.is_fin();
    if let Some(pkt) = chunk.take_packet() {
        // `pkt` (`is_unique() == true`) is forwarded directly without copying payload bytes;
        // dropping `chunk` releases receive flow-control credit automatically.
        outbound_stream.send_packet(pkt, fin).await?;
    } else {
        let (mut pkt, _) = outbound_stream.alloc_packet_async().await?;
        pkt.append(chunk.bytes()).unwrap();
        outbound_stream.send_packet(pkt, fin).await?;
    }
}
```

### 3. Low-Level `QuicMux` Engine (`#![no_std]` Core; `TokioLinkSet` Shown with `features = ["tokio"]`)

For embedded `#![no_std]` runtimes or custom event loops, implement [`AssociationEgress`](src/link.rs) and drive [`QuicMux`](src/mux.rs) directly (shown below paired with `tokio_mux::TokioLinkSet`, which requires `features = ["tokio"]`):

```rust,ignore
use quic_mux::{
    AssociationId, MuxCallbacks, MuxLimits, PacketPool, PoolPacket, QuicMux,
    RxOutcome, RxStreamChunk, SlabPacket, SlabPool, StreamError, StreamId, StreamPriority,
    TxStreamData, tokio_mux::TokioLinkSet,
};

let pool = SlabPool::with_default_geometry(64);
let mut links = TokioLinkSet::new(pool.clone(), 64);
let assoc = AssociationId(1);
links.add_stream_link(assoc, tcp_stream, 10, 32);
links.add_stream_link(assoc, uds_stream, 10, 32);

let mut mux = QuicMux::new(pool.clone(), MuxLimits::default());
mux.add_association(assoc, true).unwrap();
let stream = mux
    .open_stream_with_priority(assoc, true, StreamPriority::HIGH)
    .unwrap();

let mut pkt = pool.alloc().unwrap();
pkt.append(b"hello over multipath tcp+uds").unwrap();
mux.write_stream(assoc, stream, TxStreamData::Packet(pkt), true, &mut links)
    .unwrap();
```

### Zero-Copy Proxy / Gateway Forwarding (`#![no_std]`)

```rust,ignore
impl MuxCallbacks<SlabPacket> for ProxyHandler {
    fn on_stream_data(
        &mut self,
        _in_assoc: AssociationId,
        _in_stream: StreamId,
        _offset: u64,
        mut chunk: RxStreamChunk<'_, SlabPacket>,
        fin: bool,
    ) -> Result<RxOutcome<SlabPacket>, StreamError> {
        let len = chunk.len();
        if let Some(pkt) = chunk.take_packet() {
            // `pkt` has `is_unique() == true` and `range()` set to `144..144 + len`.
            // Forward directly onto `out_assoc` / `out_stream` with zero copies!
            self.outbound_mux
                .write_stream(self.out_assoc, self.out_stream, TxStreamData::Packet(pkt), fin, &mut self.egress)
                .ok();
        }
        Ok(RxOutcome::Consumed(len))
    }
}
```

---

## Running Tests & Loopback Throughput Comparisons

```sh
. ./env.sh
cargo test -p quic-mux -- --test-threads=1 --nocapture
cargo test -p quic-mux --release -- --test-threads=1 --nocapture
```

The 20-test suite in [`src/tests.rs`](src/tests.rs) covers:
- Zero-copy headroom prepend and exact `range()` rollback on `LinkSendError::Busy`.
- Packet-atomic malformed frame rejection, exact wire-order execution (`[STREAM, RESET_STREAM]` vs `[RESET_STREAM, STREAM]`), full 62-bit `UnsupportedFrame` varints, and both `0x1c` transport and `0x1d` application `CONNECTION_CLOSE` frames (`QuicMux::close_association`).
- Untrusted-peer stream & flow-control safety: initiator-bit and unidirectional role enforcement, `MAX_STREAMS` watermarks, pre-insertion initial flow-control checks, closed-stream anti-resurrection, `STOP_SENDING` local sender termination + automatic `RESET_STREAM`, and `RESET_STREAM.final_size` validation with association `MAX_DATA` credit reclamation.
- End-to-end 3-node zero-copy proxy forwarding (`sender -> proxy -> receiver` using a single pool slot).
- TX small-packet coalescing (`<= 1/3 MTU` via `try_coalesce_tx_packet`) and RX multi-frame `> 1/2 MTU` exclusive `PoolPacket` ownership split.
- Dual user-facing `TokioMux` / `MuxStream` tests: drop-in `AsyncRead + AsyncWrite` TCP substitute with stream churn (`MAX_STREAMS` replenishment), unidirectional streams (`open_uni`), `MuxReadHalf` drop `STOP_SENDING` propagation, zero-copy `send_packet` / `send_in_place` / `recv_chunk` / `recv_chunks_drained` + hybrid header-read gateway splicing, and dynamic server association registration + mixed-MTU multipath clamping.
- Multi-link failover, out-of-order reassembly, and missing middle-frame gap timeout (`advance_time` emitting peer `RESET_STREAM` + `STOP_SENDING`, `GapTimeout`, and `AssociationBrokenReason::StreamGapTimeout`).
- Dynamic RX out-of-order priority eviction (`QuicMux`) and standalone `SackRetransmitLedger` TX priority eviction.
- `StaticPacketPool`, `HeapPacketPool`, and `XipLazyPool` (`keep`, `trim`, `prepare_rx`, `prewarm`, generation handles, `Send + !Sync` lease bounds, and `u8::MAX` refcount saturation without wraparound).
- Loopback stress, throughput, and global-allocator memory/allocation benchmarks (`CountingAllocator` tracking `allocs`, `frees`, `alloc_kib`, `peak_kib`, and `pool_slots`) comparing `QuicMux` and `TokioMux` against [`yamux`](https://crates.io/crates/yamux) (`0.14`, `yamux::Connection` both unbuffered and wrapped in `tokio::io::BufStream` 64 KiB) over single TCP, single UDS (`UnixStream` and `UnixDatagram`), and 3-link multipath (`2 × TcpStream + 1 × UnixStream` and `1 × TcpStream + 1 × UnixStream + 1 × UnixDatagram`).
