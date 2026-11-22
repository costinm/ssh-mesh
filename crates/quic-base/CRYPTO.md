# `quic-base` Packet Protection & Key Schedule

This document summarizes the wire crypto implemented in [`src/crypto.rs`](src/crypto.rs).

## Design Goals

- **`#![no_std]` protocol core** behind a pluggable `CryptoProvider` function-pointer table:
  - **Embedded (ESP32):** `rust-crypto` feature is disabled; the device runtime supplies hardware/mbedTLS PSA Crypto (`xip_crypto.c`) for SHA-256 and AES-128-GCM / AES-128-CCM.
  - **Host (`feature = "rust-crypto"`):** uses `aes-gcm`, `sha2`, and `zeroize`.
- **Relay-transparent AEAD:** relays rewrite only the wire DCID in the short header. Endpoints reconstruct the canonical short-header AAD using their local endpoint DCID before sealing or opening, so relays never hold traffic keys.

## Primitives & Sizes

| Parameter | Value |
|---|---|
| Hash / KDF | SHA-256, HMAC-SHA256, HKDF-SHA256 (RFC 5869) |
| AEAD ciphers | AES-128-GCM (cipher `0`, default) or AES-128-CCM (cipher `1`) |
| Traffic key (`TRAFFIC_KEY_LEN`) | 16 bytes |
| Traffic IV / nonce (`TRAFFIC_IV_LEN`) | 12 bytes |
| AEAD tag (`AEAD_TAG_LEN`) | 16 bytes (appended at packet tail) |
| Association random (`ASSOCIATION_RANDOM_LEN`) | 32 bytes per endpoint |
| Compressed P-256 public key (`PUBLIC_KEY_COMPRESSED_LEN`) | 33 bytes (SEC1) |
| `Initial` verifier (`INITIAL_VERIFIER_LEN`) | 32 bytes (HMAC-SHA256) |
| Protected short-header flag (`FLAG_PROTECTED`) | `0x04` (key-phase bit in byte 0) |

## Key Derivation Hierarchy

All derivations use `HKDF-SHA256(salt, ikm, info, L)`.

### 1. Per-Device Secret (`derive_device_secret_with`)

Derived from a fleet/control root secret and the device's 33-byte compressed P-256 public key:

- **salt:** `"dmesh/control/v1"` (`CONTROL_SECRET_SALT`)
- **ikm:** `control_secret`
- **info:** `"device-credential\0" || device_public_key (33 B)`
- **output:** `node_secret` (32 B)

### 2. Per-Caller API Key (`derive_peer_api_key_with`)

Derived from a target device's `node_secret` and a caller's public key (or empty slice `&[]` for the owner key):

- **salt:** `"dmesh/quic-api-key/v1"` (`API_KEY_SALT`)
- **ikm:** `target_node_secret` (32 B)
- **info:** `"caller\0" || caller_public_key`
- **output:** `api_key` (32 B)

### 3. Directional Traffic Keys (`derive_traffic_keys_with` / `derive_static_traffic_keys_with`)

Derived per association for `Client -> Server` (`c2s`) and `Server -> Client` (`s2c`):

- **salt:** `client_random (32 B) || server_random (32 B)`
  - In **static / prekeyed mode** (`derive_static_traffic_keys_with`), both randoms are 32 zero bytes (`[0u8; 32]`) and `ikm = api_key`.
  - In **`Initial` handshake mode** (`derive_traffic_keys_with`), fresh 32-byte randoms are exchanged in `Initial` transport parameters.
- **ikm:** `psk` (32 B)
- **info:** `"dmesh/quic-lite/traffic/v1/" || client_cid_u64_be (8 B) || server_cid_u64_be (8 B) || dir`
  - `dir = "c2s\0"` for `client_to_server`
  - `dir = "s2c\0"` for `server_to_client`
- **output:** `28 B = key (16 B) || iv (12 B)` per direction.

### 4. `Initial` Handshake Verifier (`compute_initial_verifier`)

Authenticates the `Initial` handshake transcript without requiring X.509 certificates:

- `HMAC-SHA256(key = api_key, msg = "dmesh/quic-initial-v1\0" || role_byte || client_random || server_random || original_dcid_u64_be || client_cid_u64_be || server_cid_u64_be)`
  - `role_byte`: `0` for `CryptoRole::Client`, `1` for `CryptoRole::Server`.

## Per-Packet Protection (Short Header)

### Nonce

RFC 9000 §5.3 style XOR of the 12-byte directional `iv` with the big-endian `packet_number`:

- `nonce[0..8] = iv[0..8]`
- `nonce[8..12] = iv[8..12] ^ packet_number.to_be_bytes()`

### Associated Data (`canonical_short_header_aad`)

The AAD is the short header with the wire DCID replaced by the destination endpoint's `endpoint_dcid` (and `FLAG_PROTECTED = 0x04` set in byte 0):

- `aad = flags (1 B) || endpoint_dcid (1/2/4/8 B) || encoded_packet_number (1..4 B)`

Because relays only rewrite the wire DCID, `canonical_short_header_aad` produces identical AAD at sender and receiver across arbitrary relay hops.

### Wire Layout

- **UDP / NOW / LoRa / PPP (`LinkFraming::Datagram`):**
  `ShortHeader (with 0x04 set) || AEAD_ciphertext(frames) || AEAD_tag (16 B)`
- **TCP (`LinkFraming::TlsRecord`):**
  `[0x17, 0x03, 0x03, len_hi, len_lo] || ShortHeader || AEAD_ciphertext(frames) || AEAD_tag (16 B)`
  (5-byte TLS 1.3 Application Data record header delimiting each packet on the TCP byte stream).
