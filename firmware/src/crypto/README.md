# Crypto module

The `doohickey-crypto` workspace library lives here so the same `no_std`, heap-free
code can run in firmware and in host tests. Firmware modules import it through
`crate::crypto`. The blinky/button test does not generate, provision, log, or
persist any secrets automatically.

## Library choices and research

These choices were checked against published sources on November 15, 2026.
Versions are resolved in the firmware's existing `Cargo.lock`.

| Purpose | Choice | Reason |
| --- | --- | --- |
| CTAP ES256 credentials and ECDH | RustCrypto `p256` 0.13.2 | Pure Rust, no heap, P-256 signing/key agreement, validated curve points |
| Hashes, KDFs, authentication | RustCrypto `sha2`, `hmac`, `hkdf` | Compatible embedded trait ecosystem and standard algorithms |
| CTAP PIN protocol CBC | RustCrypto `aes` + `cbc` | Required CTAP encoding, portable AES implementation |
| Stored secrets | RustCrypto `chacha20poly1305` | XChaCha20-Poly1305 AEAD, random 192-bit nonces, no persistent nonce counter |
| Serial handshake | `noise-protocol` + selected `noise-rust-crypto` backends | Established Noise construction without an allocator or OS RNG |
| Serial DH | `x25519-dalek` | X25519, with an adapter rejecting all-zero DH results |
| Entropy | Embassy RP2350 `trng` + SHA-256 + `rand_chacha` | Hardware entropy checks, conditioned seed, efficient ChaCha20 CSPRNG |
| Key buffers and comparisons | `zeroize`, `subtle` | Explicit secret-buffer cleanup and constant-time authentication comparison |

The pinned RustCrypto family shares compatible `rand_core` 0.6 and cipher/digest
traits. Defaults enabling heap/OS facilities are disabled. Snow is a host-only
test dependency for independent Noise interoperability, not part of firmware's
runtime dependency graph. Broad TLS libraries or a general-purpose allocator
would add integration work this fixed serial-record use does not need.

Primary references:

- [FIDO CTAP 2.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html): P-256 key agreement; PIN protocols 1/2 use SHA-256 or HKDF, AES-256-CBC, and HMAC-SHA-256. Protocol 2 separates HMAC/AES keys and prefixes a random IV.
- [P-256 upstream security notes](https://github.com/RustCrypto/elliptic-curves/blob/p256/v0.13.2/p256/README.md): the selected release's curve arithmetic has not been independently audited; constant-time intent is not a hardware-side-channel assessment.
- [RustCrypto AEAD security notes](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/): audit history and constant-time multiplication assumptions. This does not constitute an audit of this application or every dependency version.
- [Noise specification](https://noiseprotocol.org/noise.html) and [no-std protocol library](https://docs.rs/noise-protocol/0.2.1/noise_protocol/): handshake/state handling is delegated to the protocol library.
- [Embassy TRNG source](https://docs.rs/embassy-rp/0.10.0/src/embassy_rp/trng.rs.html): hardware tests, conservative sampling guidance, and asynchronous entropy collection.
- [RFC6979](https://www.rfc-editor.org/rfc/rfc6979.html), [RFC5869](https://www.rfc-editor.org/rfc/rfc5869.html), [RFC4231](https://www.rfc-editor.org/rfc/rfc4231.html): deterministic ECDSA, HKDF, HMAC, and test vectors.

## Hardware randomness

After `embassy_rp::init`, seed a generator using the actual TRNG peripheral:

```rust,ignore
let mut entropy = crate::crypto::rng::HardwareEntropy::new(peripherals.TRNG);
let mut rng = entropy.seed_rng().await?;
let credential = crate::crypto::ctap::Es256Key::generate(&mut rng);
```

The TRNG configuration leaves autocorrelation, CRNGT, and Von Neumann checks
enabled, uses sample count 100, and collects 64 bytes before SHA-256 conditioning.
Seeding has a two-second timeout and an extra constant-output failure check.
The HAL handles health-test retries; there is no insecure fallback seed.
The constant-output check is not an entropy certification or a substitute for
the hardware tests. TRNG timeout, quality, and physical-device behavior need
hardware testing. Stop secret-generating operations if seeding fails.

Create a fresh generator after every boot and reseed periodically in long-lived
operation (e.g. before a new backup session). `DeviceRng` is not cloneable.
Private-key/root-key buffers use zeroizing owners where supported, but Rust
temporary copies, the CSPRNG's internal state, and every third-party handshake
temporary are not guaranteed to be scrubbed. Never print secret material.

## CTAP methods

`ctap::Es256Key` generates/imports P-256 keys, exports the public SEC1 point,
and signs a message with SHA-256/RFC6979, returning DER ECDSA. For assertions,
sign `authenticatorData || clientDataHash`; do not hash the concatenation first.
The public point is `0x04 || x || y`; construct COSE EC2 keys in the CTAP layer.
`secret_bytes()` is an explicit export for encryption before storage.

`PinUvKeyAgreement` uses a separate ephemeral key and derives protocol-1 or
protocol-2 `PinUvSharedSecret`. It exposes encryption/decryption and constant-time
authentication verification. COSE key parameters must also be checked by the
CTAP parser (`kty=EC2`, `crv=P-256`, `alg=-25`).

CBC is intentionally available only here for CTAP compatibility. It does not
authenticate its ciphertext. Verify the exact command-specific `pinUvAuthParam`
input before decrypting, then validate PIN length, permissions, retry counters,
and command semantics. Protocol 1 uses a zero IV and 16-byte HMAC tag; protocol
2 prefixes a fresh 16-byte IV and uses a 32-byte tag. Both require block-aligned
plaintext without automatic padding.

This is a baseline ES256/ClientPIN crypto layer, not a complete CTAP authenticator
or FIDO certification. It does not implement CBOR, attestation certificates,
credential lifecycle, optional EdDSA/RSA algorithms, or all CTAP extensions.

## Encrypting persistent secrets

`crate::otp::Otp` implements the async `MasterKeyProvider` interface for guarded
hardware reads or the explicit flash-backed test mode. See the
[OTP guide](../otp/README.md) for provisioning gates and page locking. Losing
or regenerating the root key makes previously encrypted records unreadable.
`MasterKey::generate` is an explicit provisioning operation, not startup logic.
Protect root-key access using the device's secure-boot/debug/TrustZone policy;
putting a readable key into OTP alone does not isolate it from arbitrary firmware.

```rust,ignore
use crate::crypto::secrets::{MasterKeyProvider, SecretBox};

let master = provider.load_master_key().await?;
let cipher = SecretBox::from_master_key(&master);
let mut envelope = [0u8; 1024];
// Stable AAD: record type, encoding version, and storage key. Not firmware version.
let context = b"credential/v1/key=42";
let len = cipher.seal(&mut rng, context, secret_bytes, &mut envelope)?;
storage.store(42, &envelope[..len]).await?;
```

Use the same context with `open`. Changing the key, context, ciphertext, nonce,
or tag causes authentication failure. Envelope format is
`version=1 [1] || nonce [24] || ciphertext [N] || tag [16]`. The storage map's
1024-byte value limit leaves **983 bytes** for encrypted plaintext. The header
accepts only version 1; other versions require explicit support. Output is
cleared on tag failure. Caller-owned plaintext buffers still need cleanup.

`Storage::store` remains a raw byte API. It does not automatically encrypt data
or convert old plaintext records. AEAD does not prevent rollback to an older
valid record, and log-structured flash can retain old plaintext/secret copies.
Counters, secure deletion, factory reset, and data migration need separate policy.

For firmware storage, prefer `crate::storage::EncryptedStorage` in
[`storage/encrypted.rs`](../storage/encrypted.rs). It borrows the raw store and
CSPRNG, derives its cipher from an explicitly supplied master, and automatically
binds the storage key, `RecordKind`, and stable wrapper encoding version as AAD.
Its `store`/`read` methods limit plaintext to 983 bytes and authenticate complete
records in zeroizing scratch buffers before returning plaintext. Read output is
cleared on entry, including on missing records or errors. Application payload
serialization/versioning and caller-owned plaintext cleanup remain the caller's
responsibility. See the root README for usage.

## Serial channel and credential backups

The wire protocol is `Noise_NNpsk0_25519_ChaChaPoly_SHA256` with prologue
`DOOHICKEY serial backup v1`. The host is the initiator, the authenticator the
responder. A pair-specific **random 32-byte PSK** authenticates both sides.
Provision/pin this key over an authenticated out-of-band process. A short PIN,
unauthenticated ECDH, a hardcoded development key, or sending the PSK over the
same serial link is not secure pairing. Do not reuse the OTP root as the PSK.

`PairingKey::generate` uses the caller's CSPRNG. Securely store/export the key
only through an explicit pairing flow. The private DH adapter injects a fresh
random ephemeral into each Noise handshake and rejects low-order/all-zero
shared secrets. Its implicit generation hook deliberately fails closed instead
of using an OS RNG. No application payloads are accepted during the handshake.

1. Construct `SerialHandshake::new(true/false, &pairing_key, &mut rng)`.
2. Host `write_message`: send exactly 48 bytes; device `read_message`.
3. Device `write_message`: send exactly 48 bytes; host `read_message`.
4. Consume each handshake using `finish()`; then use `seal`/`open` on sessions.

For UART/USB CDC framing, prefix each Noise record with its two-byte big-endian
length. Bound handshake lengths to 48 and transport lengths to 16..=1040 before
buffering; handle partial reads and enforce a timeout. The length prefix is not
secret. Changing the record boundaries cannot create authenticated plaintext;
it fails authentication or closes the connection. The caller owns I/O framing
and should close on framing/timeouts, not skip damaged records and keep going.

The firmware's [USB CDC adapter](../usb/README.md) now implements bounded stream
framing and connection resets. Its current application handler supports public
INFO only; it does not run this Noise handshake or authorize backups yet.

Transport plaintext is limited to 1024 bytes. Directional cipher keys and
implicit 64-bit counters reject reflection, replay, and reordering. A bad tag
closes the session and clears tentative plaintext; use a new handshake after
disconnect or failure. Session objects are not cloneable or serializable, and
nonce exhaustion fails closed. Never reuse session counters with old keys.

Authenticate the complete backup message type, object identifiers, chunk index,
transfer ID, total length, and final digest inside encrypted payloads. Require
an explicit final commit so truncation/partial backups are not accepted as
complete. The record layer alone cannot detect a peer disconnecting before an
application-declared transfer completes. Bind physical user-presence/backup
authorization to `channel_binding()` and require it before exporting credentials.

The channel protects transfer, not a backup file after receipt. A portable
backup needs a separate recovery-key/encryption policy; the device-bound root
key is not automatically available on a replacement device. This module does
not add UART commands, a browser client, a pairing UI, or automatic export.

## Validation

From `firmware/`, run host tests using your host target (replace the example
target on macOS/ARM Linux with the `host:` reported by `rustc -vV`):

```sh
cargo test -p doohickey-crypto --target x86_64-unknown-linux-gnu
cargo build --release --bins --examples --target-dir target/4mb
cargo build --release --bins --examples --features flash-16mb --target-dir target/16mb
```

An opt-in hardware test exercises TRNG seeding, key generation, signing,
encryption, and a loopback Noise handshake without OTP programming or storage
writes. With an SWD probe, run it using the correct flash-size selection:

```sh
DEFMT_LOG=info cargo run --release --example crypto_smoke --target-dir target/4mb
# For a 16 MiB board, also pass --features flash-16mb.
```

It reports pass/fail through RTT without printing keys or random bytes. It is
a functional hardware check, not an entropy statistical/certification test.

Tests cover SHA/HMAC/HKDF and deterministic ECDSA vectors, NIST AES-CBC,
PIN protocol agreement/IV/tag encoding, tampered envelopes, wrong keys/context,
malformed lengths, serial replay/reflection/reordering, wrong PSKs, and Noise
interoperability with the independent Snow handshake implementation. They do
not establish hardware entropy quality, side-channel resistance, secure OTP
provisioning, or end-to-end backup application security. Obtain an independent
review before using this as a real credential authenticator.
