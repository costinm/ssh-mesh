#![cfg(all(feature = "rust-crypto", feature = "host-pools"))]

use std::hint::black_box;
use std::time::Instant;

use aes_gcm::{Aes128Gcm, KeyInit as AeadKeyInit, Nonce, Tag, aead::AeadInPlace};
use quic_base::pool::{DEFAULT_HEADROOM, PacketPool, PoolPacket, XipLazyPool};
use quic_base::{
    AEAD_TAG_LEN, ConnectionId, CryptoProvider, CryptoRole, DirectionKeyMaterial, PacketCrypto,
    ProviderAeadKey, PUBLIC_KEY_COMPRESSED_LEN, ShortHeader, compute_initial_verifier_with,
    derive_device_secret_with, derive_peer_api_key_with, derive_static_traffic_keys_with,
    derive_traffic_keys_with, open_short_packet_in_place, seal_short_packet_in_place,
    verify_initial_verifier_with, vip6_from_public_key_with,
};

#[cfg(target_os = "linux")]
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[cfg(target_os = "linux")]
fn thread_cpu_ns() -> u64 {
    const CLOCK_THREAD_CPUTIME_ID: i32 = 3;
    unsafe extern "C" {
        fn clock_gettime(clk_id: i32, tp: *mut Timespec) -> i32;
    }
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { clock_gettime(CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    if rc == 0 {
        (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
    } else {
        0
    }
}

#[cfg(not(target_os = "linux"))]
fn thread_cpu_ns() -> u64 {
    0
}

struct CachedAes128Gcm {
    cipher: Aes128Gcm,
    iv: [u8; 12],
}

impl CachedAes128Gcm {
    fn new(key: &[u8; 16], iv: [u8; 12]) -> Self {
        Self {
            cipher: Aes128Gcm::new_from_slice(key).expect("16B AES-128 key"),
            iv,
        }
    }
}

impl PacketCrypto for CachedAes128Gcm {
    fn seal_in_place(
        &self,
        packet_number: u32,
        associated_data: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; AEAD_TAG_LEN], quic_base::CryptoError> {
        let nonce = quic_base::make_packet_nonce(&self.iv, packet_number);
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), associated_data, body)
            .map_err(|_| quic_base::CryptoError::Invalid)?;
        let mut out = [0u8; AEAD_TAG_LEN];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    fn open_in_place(
        &self,
        packet_number: u32,
        associated_data: &[u8],
        body: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<(), quic_base::CryptoError> {
        let nonce = quic_base::make_packet_nonce(&self.iv, packet_number);
        self.cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), associated_data, body, Tag::from_slice(tag))
            .map_err(|_| quic_base::CryptoError::AuthenticationFailed)
    }
}

struct NoopCrypto;

impl PacketCrypto for NoopCrypto {
    fn seal_in_place(
        &self,
        _packet_number: u32,
        _associated_data: &[u8],
        _body: &mut [u8],
    ) -> Result<[u8; AEAD_TAG_LEN], quic_base::CryptoError> {
        Ok([0u8; AEAD_TAG_LEN])
    }

    fn open_in_place(
        &self,
        _packet_number: u32,
        _associated_data: &[u8],
        _body: &mut [u8],
        _tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<(), quic_base::CryptoError> {
        Ok(())
    }
}

fn iters_for_size(sz: usize) -> usize {
    match sz {
        0..=256 => 100_000,
        257..=1200 => 40_000,
        _ => 25_000,
    }
}

#[test]
#[ignore]
fn bench_quic_base_aead_and_handshake_primitives() {
    let provider = CryptoProvider::rust_crypto();
    let key = [0x42u8; 16];
    let iv = [0x24u8; 12];
    let aad = [0x01u8; 11];
    let cached_cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv);

    println!("=== quic-base AEAD primitive microbenchmark (host x86_64 release, AES-128-GCM) ===");
    println!(
        "{:<8} {:<26} {:>10} {:>10} {:>10} {:>10}",
        "Size", "Mode", "Wall ns/op", "CPU ns/op", "MiB/s", "Mbps"
    );

    for &sz in &[64usize, 256, 1024, 1200, 1400] {
        let iters = iters_for_size(sz);
        let mut buf = vec![0xabu8; sz];
        let mut copy_dst = vec![0u8; sz];

        // 1. Cleartext memcpy baseline
        for _ in 0..1000 {
            copy_dst.copy_from_slice(black_box(&buf));
            black_box(&copy_dst);
        }
        let c0 = thread_cpu_ns();
        let t0 = Instant::now();
        for i in 0..iters {
            buf[0] = (i & 0xff) as u8;
            copy_dst.copy_from_slice(black_box(&buf));
            black_box(&copy_dst);
        }
        let wall_ns = t0.elapsed().as_nanos() as f64 / iters as f64;
        let cpu_ns = (thread_cpu_ns().saturating_sub(c0)) as f64 / iters as f64;
        let mibs = (sz as f64 * 1e9) / (wall_ns * (1024.0 * 1024.0));
        let mbps = (sz as f64 * 8.0 * 1e9) / (wall_ns * 1e6);
        println!(
            "{:<8} {:<26} {:>10.1} {:>10.1} {:>10.1} {:>10.1}",
            sz, "cleartext_memcpy", wall_ns, cpu_ns, mibs, mbps
        );

        // 2. CryptoProvider::rust_crypto() seal+open (new_from_slice per op)
        for _ in 0..500 {
            let tag = (provider.aead_seal)(0, &key, &nonce, &aad, &mut buf).unwrap();
            (provider.aead_open)(0, &key, &nonce, &aad, &mut buf, &tag).unwrap();
        }
        let c0 = thread_cpu_ns();
        let t0 = Instant::now();
        for i in 0..iters {
            nonce[8..12].copy_from_slice(&(i as u32).to_be_bytes());
            let tag = (provider.aead_seal)(0, &key, &nonce, &aad, black_box(&mut buf)).unwrap();
            black_box(tag);
        }
        let seal_wall_ns = t0.elapsed().as_nanos() as f64 / iters as f64;
        let seal_cpu_ns = (thread_cpu_ns().saturating_sub(c0)) as f64 / iters as f64;

        // Precompute one sealed buffer for open benchmark
        nonce[8..12].copy_from_slice(&0u32.to_be_bytes());
        let mut cipher_buf = vec![0xabu8; sz];
        let tag_fixed = (provider.aead_seal)(0, &key, &nonce, &aad, &mut cipher_buf).unwrap();
        let mut scratch = vec![0u8; sz];
        let c0 = thread_cpu_ns();
        let t0 = Instant::now();
        for _ in 0..iters {
            scratch.copy_from_slice(&cipher_buf);
            (provider.aead_open)(0, &key, &nonce, &aad, black_box(&mut scratch), &tag_fixed)
                .unwrap();
        }
        let open_wall_ns = t0.elapsed().as_nanos() as f64 / iters as f64;
        let open_cpu_ns = (thread_cpu_ns().saturating_sub(c0)) as f64 / iters as f64;

        for (label, w, c) in [
            ("rust_crypto_seal_uncached", seal_wall_ns, seal_cpu_ns),
            ("rust_crypto_open_uncached", open_wall_ns, open_cpu_ns),
            (
                "rust_crypto_seal+open",
                seal_wall_ns + open_wall_ns,
                seal_cpu_ns + open_cpu_ns,
            ),
        ] {
            let mibs = (sz as f64 * 1e9) / (w * (1024.0 * 1024.0));
            let mbps = (sz as f64 * 8.0 * 1e9) / (w * 1e6);
            println!(
                "{:<8} {:<26} {:>10.1} {:>10.1} {:>10.1} {:>10.1}",
                sz, label, w, c, mibs, mbps
            );
        }

        // 3. Cached Aes128Gcm seal & open
        let c0 = thread_cpu_ns();
        let t0 = Instant::now();
        for i in 0..iters {
            nonce[8..12].copy_from_slice(&(i as u32).to_be_bytes());
            let tag = cached_cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, black_box(&mut buf))
                .unwrap();
            black_box(tag);
        }
        let c_seal_w = t0.elapsed().as_nanos() as f64 / iters as f64;
        let c_seal_c = (thread_cpu_ns().saturating_sub(c0)) as f64 / iters as f64;

        nonce[8..12].copy_from_slice(&0u32.to_be_bytes());
        let c0 = thread_cpu_ns();
        let t0 = Instant::now();
        for _ in 0..iters {
            scratch.copy_from_slice(&cipher_buf);
            cached_cipher
                .decrypt_in_place_detached(
                    Nonce::from_slice(&nonce),
                    &aad,
                    black_box(&mut scratch),
                    Tag::from_slice(&tag_fixed),
                )
                .unwrap();
        }
        let c_open_w = t0.elapsed().as_nanos() as f64 / iters as f64;
        let c_open_c = (thread_cpu_ns().saturating_sub(c0)) as f64 / iters as f64;

        for (label, w, c) in [
            ("cached_aes_gcm_seal", c_seal_w, c_seal_c),
            ("cached_aes_gcm_open", c_open_w, c_open_c),
            (
                "cached_aes_gcm_seal+open",
                c_seal_w + c_open_w,
                c_seal_c + c_open_c,
            ),
        ] {
            let mibs = (sz as f64 * 1e9) / (w * (1024.0 * 1024.0));
            let mbps = (sz as f64 * 8.0 * 1e9) / (w * 1e6);
            println!(
                "{:<8} {:<26} {:>10.1} {:>10.1} {:>10.1} {:>10.1}",
                sz, label, w, c, mibs, mbps
            );
        }
    }

    // 4. ShortHeader in-place roundtrip (ProviderAeadKey vs CachedAes128Gcm vs Noop)
    println!("\n=== ShortHeader seal+open in-place (PoolPacket, DCID=1, PN=100) ===");
    println!(
        "{:<8} {:<26} {:>10} {:>10} {:>10}",
        "Payload", "PacketCrypto", "Wall ns/op", "CPU ns/op", "Goodput%"
    );
    let pool = XipLazyPool::with_default_geometry(8);
    let cid = ConnectionId::new(1).unwrap();
    let pkey = ProviderAeadKey::new(provider, DirectionKeyMaterial { key, iv });
    let ckey = CachedAes128Gcm::new(&key, iv);
    let nkey = NoopCrypto;

    for &sz in &[64usize, 256, 1024, 1200, 1400] {
        let iters = iters_for_size(sz);
        let mut hdr = [0u8; 16];
        let sh = ShortHeader {
            flags: 0,
            dcid: cid,
            packet_number: 100,
            packet_number_len: 1,
        };
        let hdr_len = sh.encode(&mut hdr).unwrap();
        let body = vec![0x5au8; sz];

        let mut pkt = pool.alloc_with_headroom(DEFAULT_HEADROOM).unwrap();
        let run_short = |pkt: &mut quic_base::pool::XipLazyPacket, crypto: &dyn PacketCrypto| -> (f64, f64) {
            for _ in 0..500 {
                pkt.set_range(DEFAULT_HEADROOM..DEFAULT_HEADROOM).unwrap();
                pkt.append(&hdr[..hdr_len]).unwrap();
                pkt.append(&body).unwrap();
                seal_short_packet_in_place(pkt, crypto, cid).unwrap();
                let flags = pkt.bytes()[0];
                open_short_packet_in_place(pkt, crypto, flags, hdr_len, 100, 1, cid).unwrap();
            }
            let c0 = thread_cpu_ns();
            let t0 = Instant::now();
            for _ in 0..iters {
                pkt.set_range(DEFAULT_HEADROOM..DEFAULT_HEADROOM).unwrap();
                pkt.append(&hdr[..hdr_len]).unwrap();
                pkt.append(&body).unwrap();
                seal_short_packet_in_place(pkt, crypto, cid).unwrap();
                let flags = pkt.bytes()[0];
                open_short_packet_in_place(pkt, crypto, flags, hdr_len, 100, 1, cid).unwrap();
                black_box(pkt.bytes());
            }
            let w = t0.elapsed().as_nanos() as f64 / iters as f64;
            let c = (thread_cpu_ns().saturating_sub(c0)) as f64 / iters as f64;
            (w, c)
        };

        let (nw, nc) = run_short(&mut pkt, &nkey);
        let (pw, pc) = run_short(&mut pkt, &pkey);
        let (cw, cc) = run_short(&mut pkt, &ckey);

        let clear_wire = hdr_len + sz;
        let enc_wire = hdr_len + sz + AEAD_TAG_LEN;
        println!(
            "{:<8} {:<26} {:>10.1} {:>10.1} {:>9.2}%",
            sz,
            "noop (0B tag)",
            nw,
            nc,
            100.0 * sz as f64 / clear_wire as f64
        );
        println!(
            "{:<8} {:<26} {:>10.1} {:>10.1} {:>9.2}%",
            sz,
            "ProviderAeadKey (uncached)",
            pw,
            pc,
            100.0 * sz as f64 / enc_wire as f64
        );
        println!(
            "{:<8} {:<26} {:>10.1} {:>10.1} {:>9.2}%",
            sz,
            "CachedAes128Gcm (+16B tag)",
            cw,
            cc,
            100.0 * sz as f64 / enc_wire as f64
        );
    }

    // 5. Key derivation & Initial verifier ops (CompactSha256 + HKDF)
    println!("\n=== Key Derivation & Handshake Verifier Primitives (CompactSha256) ===");
    let pub_key = [0x02u8; PUBLIC_KEY_COMPRESSED_LEN];
    let rand_a = [0x1au8; 32];
    let rand_b = [0x2bu8; 32];
    let node_secret =
        derive_device_secret_with(&provider, b"bench-root-secret-material-32byte", &pub_key)
            .unwrap();
    let api_key = derive_peer_api_key_with(&provider, &node_secret, &pub_key).unwrap();
    let verifier = compute_initial_verifier_with(
        &provider,
        &api_key,
        CryptoRole::Client,
        Some(ConnectionId::new(11).unwrap()),
        Some(ConnectionId::new(0x1234_5678).unwrap()),
        &pub_key,
        &rand_a,
    )
    .unwrap();

    let h_iters = 5_000usize;
    macro_rules! bench_op {
        ($name:expr, $expr:expr) => {{
            for _ in 0..100 {
                black_box($expr);
            }
            let c0 = thread_cpu_ns();
            let t0 = Instant::now();
            for _ in 0..h_iters {
                black_box($expr);
            }
            let w = t0.elapsed().as_nanos() as f64 / h_iters as f64;
            let c = (thread_cpu_ns().saturating_sub(c0)) as f64 / h_iters as f64;
            println!(
                "{:<36} {:>10.1} ns wall  {:>10.1} ns cpu  ({:>8.0} ops/s)",
                $name,
                w,
                c,
                1e9 / w
            );
        }};
    }

    bench_op!(
        "vip6_from_public_key",
        vip6_from_public_key_with(&provider, &pub_key).unwrap()
    );
    bench_op!(
        "derive_device_secret",
        derive_device_secret_with(&provider, b"bench-root-secret-material-32byte", &pub_key).unwrap()
    );
    bench_op!(
        "derive_peer_api_key",
        derive_peer_api_key_with(&provider, &node_secret, &pub_key).unwrap()
    );
    bench_op!(
        "compute_initial_verifier",
        compute_initial_verifier_with(
            &provider,
            &api_key,
            CryptoRole::Client,
            Some(ConnectionId::new(11).unwrap()),
            Some(ConnectionId::new(0x1234_5678).unwrap()),
            &pub_key,
            &rand_a,
        )
        .unwrap()
    );
    bench_op!(
        "verify_initial_verifier",
        verify_initial_verifier_with(
            &provider,
            &api_key,
            CryptoRole::Client,
            Some(ConnectionId::new(11).unwrap()),
            Some(ConnectionId::new(0x1234_5678).unwrap()),
            &pub_key,
            &rand_a,
            &verifier,
        )
        .unwrap()
    );
    bench_op!(
        "derive_static_traffic_keys",
        derive_static_traffic_keys_with(
            &provider,
            &api_key,
            ConnectionId::new(1).unwrap(),
            ConnectionId::new(1).unwrap(),
        )
        .unwrap()
    );
    bench_op!(
        "derive_traffic_keys (Initial)",
        derive_traffic_keys_with(
            &provider,
            &api_key,
            &rand_a,
            &rand_b,
            ConnectionId::new(11).unwrap(),
            ConnectionId::new(77).unwrap(),
        )
        .unwrap()
    );
}
