# Durable initialization

The coordinator implements first setup, validated resume, and startup loading.
It owns persistent state; after hardware setup, `main` inspects it, then runs
USB alongside the local button/setup loop. USB diagnostics remain available while
waiting for confirmation. Secure-boot activation, CTAP algorithms and factory
reset remain separate stages in the [alpha roadmap](../../../docs/alpha-roadmap.md).

## Try the flash-only test backend

From `firmware/`, build without touching hardware:

```sh
cargo build --locked --release --features insecure-test-otp --target-dir target/otp-test-4mb
# 16 MiB: use flash-16mb,insecure-test-otp and target/otp-test-16mb.
```

To flash and monitor using the debug probe:

```sh
DEFMT_LOG=info cargo run --release --features insecure-test-otp --target-dir target/otp-test-4mb
```

1. Use the correct flash capacity and keep the same OTP backend for subsequent
   test updates. The emulator stores its root in plaintext flash; use test data.
2. Inspect RTT or serial `INFO`. A blank test device reports `setup_required`.
3. With the button connected between GPIO 23 and GND, release it, hold it for
   **three seconds**, and release again. Both releases debounce for 30 ms.
   A button already held at boot is not confirmation.
4. The firmware seeds its RNG from the hardware TRNG, initializes, verifies the
   persisted outcome, and reports `ready`. Send INFO again to see live state.
5. Reboot or install a compatible image with the same backend/capacity, without
   erasing storage. Startup must report `ready` using the existing records;
   neither a button press nor key generation is needed again.

A confirmation window lasts 30 seconds. If it expires, the loop starts another
window requiring release and a fresh hold; a completed confirmation expires
after 10 seconds and is consumed once. Confirmation authorizes this local setup
attempt, not arbitrary operations, CTAP permissions or client authentication.
Once ready, this loop ignores the button; it does not reset the authenticator.

Default hardware builds can read already provisioned OTP and initialize empty
application storage using an existing sealed root. **New real root programming
and sealing additionally require the existing `otp-provisioning` build feature
and physical confirmation.** These operations permanently program OTP page 16.
No build/test command here programs fuses. This coordinator never writes the
secure-boot key hash, key-valid flags, secure-boot enable, or debug/boot policy.

## Persistent records

Normal application Storage read/store calls reject all three coordinator keys.

| Key | Encoding | Purpose |
| --- | --- | --- |
| `0xFFFFFE00` | 57 bytes: `DOOHSET1`, root mode, random 16-byte setup ID, SHA-256 checksum | Setup journal written/read back before root programming |
| `0xFFFFFE01` | 141-byte XChaCha20-Poly1305 envelope, containing 100 authenticated plaintext bytes | Settings and random credential key stored together; includes setup ID/journal digest |
| `0xFFFFFE02` | 113-byte encrypted/authenticated envelope containing 72 plaintext bytes | Final commit: `DOOHDONE`, journal digest, exact state-envelope digest |

The journal is not secret and its checksum is not authentication. It is never
accepted as authorization. Final state and completion authenticate the journal
identity under the sealed root. The state also carries fixed `DOOHCFG1` and
`COMPLETE` encoding markers; those markers alone do not establish readiness.

The state stores `Settings::user_presence_timeout_ms`, default 30,000 and validated
in the range 1,000..120,000, plus a random 256-bit mutable credential key.
This setting is for the future authenticator's user-presence policy; the local
setup confirmation timings above are fixed. There is no default PIN/password or
claim that the remaining CTAP persistent state has been initialized.

The mutable key is distinct from the permanent OTP root. Future credential
encryption/wrapping should use `Initialized::credential_key()`, so authenticator
reset can replace that key without replacing OTP. Reset and mutable settings
updates are not provided by this setup-only API: changing committed records
later needs its own consistent update/reset transaction.

Journal, state and completion have separate fixed encodings/AEAD contexts that
do not depend on firmware version or flash capacity. Top-level metadata remains
exactly the existing `DOOHICKEY` magic and one firmware version field. No separate
schema/layout version fields are added.

## Setup sequence and readiness

Inspection is independent of randomness. It checks the selected partition,
metadata compatibility, validated OTP record/lock state and all existing setup
records. It never generates keys or requests metadata creation. Normal storage
reads/iteration can perform the log library's existing interrupted-write repair.

After consuming a fresh local confirmation and rechecking authoritative state:

1. Initialize metadata only when permitted by the storage API; never format.
2. Write and read back a setup journal if absent. It records whether setup
   started with a blank root or an existing sealed root.
3. For a genuinely blank, provisionable root, generate/program it once. Seal it,
   verify the policy, and reload via the sealed reader. A complete valid unsealed
   root can resume sealing only with our valid new-root journal and fresh consent.
   Partial/corrupt records or unfamiliar locks require recovery.
4. If state is absent and there is no surviving completion witness, generate a
   credential key and default settings, encrypt/store them together, then reload
   and verify the key. If valid prepared state already exists, reuse it unchanged.
5. Write the authenticated completion record **last**, binding the persisted state
   and journal. Read back and authenticate all required records.
6. Retain only validated settings and the zeroizing mutable credential key,
   immediately dropping temporary root/key/plaintext buffers. Report `ready`.

If a write reports failure after it actually committed, inspection reports the
actual persisted outcome; the operation can return an error while diagnostics
already show verified readiness. Never use a transport acknowledgement alone
as proof of either successful setup or a need to regenerate secrets.

## Startup and recovery states

| State/reason | Behavior |
| --- | --- |
| `setup_required` | Blank root with erased storage, or known metadata/journal-only interrupted setup; physical confirmation required |
| `provisioning_disabled` reason | Required root writes are not compiled in; setup is blocked before any write |
| `initialization_required / storage_erased` | Sealed root with erased storage; explicit initialization preserves the root |
| `initialization_required / setup_interrupted` | Recognized journal/prepared state, no final commit; explicitly resume using any already persisted key |
| `initializing` | Local attempt is active; current INFO reports this while the setup future yields |
| `ready` | Sealed root, valid settings/key state and matching authenticated completion have all been verified |
| `migration_required` | Unsupported stored firmware version; no automatic rewrite, downgrade or migration |
| `recovery_required` | Corruption, missing required evidence, unknown application data before completion, inaccessible storage/OTP, or partial/invalid root |

If the state disappears but its completion survives, recovery is mandatory.
A missing completion with valid prepared state may be explicitly finalized,
reusing the same key, when no unrelated application records exist. An invalid
completion/state/journal is not silently replaced. Missing root alongside state
or completion is never treated as a new device.

Setup/resume scans all returned log items and permits only metadata, the three
setup keys, and (in emulator builds only) reserved emulated-OTP records. Even an
obsolete unrelated record blocks inference. A completed valid installation can
of course contain other application records. Missing metadata on non-erased
flash always blocks; metadata-only valid interrupted setup can resume explicitly.

Checksums/log recovery can make damaged writes disappear from logical reads.
The separate commit detects lost state when it survives. Loss of all mutable
evidence cannot be distinguished from an erased/incomplete installation using an
immutable root alone; reinitialization still requires physical confirmation.
This is not backup, physical secure deletion, adversarial flash rollback
protection, or recovery of a partially burned OTP root.

## Upgrades and application integration

`storage_version_supported(stored, running)` explicitly supports the current
running version and the implemented `0.1.0` persistent format. A compatible
successor must retain appropriate supported versions; arbitrary semver patch
numbers are not assumed compatible. Startup does not rewrite the stored
version. Unknown/newer formats stay blocked until an explicit migration exists.

`Coordinator<B>` runs against a narrow async `Backend`; `DeviceBackend` adapts
the existing Storage and OTP modules. On hardware, OTP record validation checks
the full record and permitted locks before offering seal resume. With the
emulator, entirely erased storage implies a blank test root without creating
metadata merely to inspect it. There is no fallback between OTP backends.

After `inspect()` or successful `initialize()`, `initialized()` exposes settings
and the credential key only for verified ready state. `Report` contains only
public diagnostics. The currently unfinished CTAP backend and serial
authentication still report unavailable even when base initialization is ready.
Serial remains INFO-only; opening a port or sending commands cannot authorize
setup. Shared status is a core-0 Cell, not accessed from USB interrupts.

## Verification

```sh
cargo test --locked -p doohickey-crypto --test initialization --target x86_64-unknown-linux-gnu
cargo test --locked -p doohickey-crypto --test otp --target x86_64-unknown-linux-gnu
cargo test --locked -p doohickey-crypto --test usb --target x86_64-unknown-linux-gnu
```

Host tests run the actual coordinator/codecs/crypto with memory-backed I/O,
inject failures before and after each durable write, and exercise confirmation,
corruption, cross-generation records, missing records/root, entropy failure,
no-write startup and a simulated compatible firmware update with the original
encrypted marker. OTP tests also exercise partial row programming and the real
flash adapter's status checks. They do not establish physical flash/OTP behavior;
qualify real power loss and guarded-read faults on controlled hardware.
