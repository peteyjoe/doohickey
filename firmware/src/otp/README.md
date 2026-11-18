# OTP key storage

`crate::otp::Otp` exposes typed, async operations for two 32-byte values:

- `read_master_key`, `provision_master_key`, and `seal_master_key`.
- `master_key_status` validates blank/unsealed/sealed state without exporting
  unsealed secret bytes. Partial/corrupt records and unfamiliar locks are errors.
- `read_secure_boot_key_hash` and `provision_secure_boot_key_hash`.

There is no generic address/key API, erase, overwrite, automatic key generation,
or fallback from hardware OTP to flash. Constructors do not program anything.
Master keys have no Debug/Clone implementation and use zeroizing buffers.

The [initialization coordinator](../init/README.md) now implements local
button-confirmed root provisioning/resume and durable application setup. It uses
these APIs, respects the existing build gates, and never configures secure boot.

## Hardware mode (default)

```rust,ignore
use crate::otp::Otp;

let mut otp = Otp::new()?;
let master = otp.read_master_key().await?;
let cipher = crate::crypto::secrets::SecretBox::from_master_key(&master);
```

Only one hardware handle can exist, it must be created on core 0, and it is
not Send/Sync. This is for the firmware's Arm Secure execution environment.
Do not access OTP through other HAL/ROM APIs concurrently with this module.

The master record reserves **all of application OTP page 16**, rows
`0x400..=0x43f`. Confirm that no other provisioning system owns this page before
deploying this layout. The record occupies 38 ECC rows: eight-byte magic,
32-byte key, SHA-256 integrity checksum, and a four-byte commit marker written
last. It spans complete adjacent row pairs for guarded ECC reads (including
the RP2350 E17 consideration). Zero/FF keys and nonblank/partially programmed
pages are rejected; a partially burned key is never silently replaced.

Reading a master key requires the page's hard LOCK1 value to be `0x3D3D3D`:
Secure read-only, Non-secure inaccessible, and bootloader inaccessible, with
all redundant copies set. `seal_master_key()` verifies the record first and
then programs that policy. It is permanent, idempotent once complete, and will
reject an unfamiliar/partial lock configuration. It does not alter LOCK0.

Reads use the **guarded** raw/ECC aliases. Ordinary permission preflight failures
return an error; the guarded hardware can raise a bus fault on ECC errors,
permission changes, or transient consistency failures. This is deliberate
fail-stop behavior, not a recover-and-use-a-default-key path.

Normal firmware builds reject programming/sealing calls with
`ProvisioningDisabled`. To compile real programming operations, explicitly use:

```sh
cargo build --release --features otp-provisioning --target-dir target/provisioning-4mb
# Add flash-16mb for a 16 MiB board.
```

Building does not burn anything. Calling these methods in running provisioning
firmware does. An authorized provisioning flow generates a root using the TRNG,
calls `provision_master_key(&master).await`, and explicitly calls
`seal_master_key().await` after verification. No test/example calls real OTP
programming functions automatically. The module intentionally cannot erase,
rotate, or repair an interrupted key burn. Keep a reviewed recovery/manufacturing
plan before using irreversible operations on real devices.

## Secure boot key hash

BOOTKEY0 occupies rows `0x80..=0x8f` in the ROM-defined layout. The stored value
is a SHA-256 fingerprint of the **secp256k1 public signing key**, not the private
signing key and not a CTAP P-256 credential key. Keep the private signing key
off-device. Supply the exact 32-byte boot-key hash from a verified Raspberry Pi
provisioning workflow; bytes 0/1 become the little-endian halfword at row 0x80.

The module verifies programming readback and refuses a populated, valid, or
revoked slot. It does **not** set KEY_VALID/KEY_INVALID, SECURE_BOOT_ENABLE,
debug-disable, boot-path configuration, or page-2 locks. Reading a populated
hash does not mean that it is activated or that secure boot is enabled. Complete
and verify that separate device-wide secure-boot policy with official tooling.

Master-page locks alone do not protect the key from arbitrary Secure firmware
or an enabled Secure debugger. Production also requires an appropriate signed
boot, debug, bootloader, and TrustZone policy. This module does not claim to
configure the complete device security policy.

References: [Raspberry Pi security guide](https://pip-assets.raspberrypi.com/categories/1260-security/documents/RP-009377-WP-1-Understanding%20RP2350_s%20security%20features.pdf),
[official OTP row/lock definitions](https://github.com/raspberrypi/pico-sdk/blob/master/src/rp2350/hardware_regs/include/hardware/regs/otp_data.h),
and [RP2350 datasheet](https://pip-assets.raspberrypi.com/categories/1214-rp2350/documents/RP-008373-DS-3-rp2350-datasheet.pdf)
(OTP guarded reads, ECC/ROM otp_access, and secure-boot provisioning sections).

## Flash-backed testing

Enable **`insecure-test-otp`** to compile only the flash backend. It cannot be
combined with `otp-provisioning`; the build rejects that combination. The build
also prints an explicit INSECURE TEST OTP warning. Keep these artifacts separate
from production outputs:

```sh
cargo build --release --features insecure-test-otp --target-dir target/otp-test-4mb
cargo build --release --features flash-16mb,insecure-test-otp --target-dir target/otp-test-16mb
```

Initialize the regular store's metadata first, then borrow it:

```rust,ignore
storage.initialize_metadata().await?;
let mut otp = crate::otp::Otp::new(&mut storage);
// Same async key methods as hardware mode.
```

The backend uses Storage keys `0xFFFFFF00` (master record), `0xFFFFFF01` (boot
hash record), and `0xFFFFFF02` (emulated seal). These keys are reserved against
normal Storage read/store calls in every build. The internal flash path requires
valid storage metadata and wipes its scratch buffer after use. Both values use
the checksummed record encoding; writes are first-write-only, and the master
must be explicitly sealed before loading. Storage errors never generate or
replace a key. The emulated seal does not provide hardware security.

**Test master keys are plaintext in external flash.** Erasing storage deletes
them and may leave encrypted test records undecryptable; log-structured flash
may retain old copies. Never use production secrets with this feature. Test
boot hashes do not participate in the RP2350 ROM's actual secure-boot checks.

Both backends implement the crypto library's async `MasterKeyProvider`:

```rust,ignore
use crate::crypto::secrets::MasterKeyProvider;
let master = otp.load_master_key().await?;
```

The provider maps failures to `crypto::Error::KeyUnavailable`; direct OTP methods
retain specific OTP error codes. No key bytes appear in errors.

## Testing

Host tests exercise the actual record codec, hardware write/lock policy, and
flash adapter against memory-backed mocks, including interrupted writes at
every programming step, corruption, reserved-page collisions, overwrite
rejection, sealing, and persistence across handles:

```sh
cargo test -p doohickey-crypto --target x86_64-unknown-linux-gnu
```

Replace the host target on macOS/ARM Linux as described in the crypto guide.
The flash-only on-board smoke test uses the TRNG, provisions test records when
absent, and checks an encrypted marker across reboots/firmware updates:

```sh
DEFMT_LOG=info cargo run --release --example otp_smoke \
  --features insecure-test-otp --target-dir target/otp-test-4mb
# Use flash-16mb,insecure-test-otp and target/otp-test-16mb for 16 MiB.
```

It never accesses real OTP, logs no key values, and fails instead of overwriting
malformed/unsealed records. Real fuse programming/locking, guarded-read fault
behavior, and device security policy still need controlled hardware validation.
The first run reports initialization; after a reboot/update, require the
"persistence verified" message using the previously stored encrypted marker.
If the marker exists but the root key is missing, it refuses to generate a
replacement key. Reinitialization after a complete erase is not proof of
persistence.
