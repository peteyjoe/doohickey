# Reset, recovery and firmware upgrades

Firmware **0.2.0** adds a durable reset and upgrade lifecycle. One image per
flash capacity handles initial setup and later updates. The storage boundary
remains flash offset `0x00300000`; ordinary updates write only the first 3 MiB.
Hardware validation and lengthy interoperability tests are still deferred.

## Factory reset

Use authenticatorReset (`0x07`) through a native/platform FIDO management tool.
Reconnect power immediately before requesting reset: the request must reach the
application within ten seconds of boot. Timing uses the device's monotonic clock,
not host timestamps; slow boot/USB enumeration can shorten the usable window.
Release BOOTSEL, hold it for **three seconds**, then release. GPIO 25 flashes
rapidly while the CTAP request waits. A held-at-boot button cannot confirm reset.
The confirmation window is 30 seconds, with debounce on both releases.

With the existing python-fido2 environment, a native reset command is
`python3 tools/pin_manage.py reset` from `firmware/`. Reconnect power immediately
before invoking it. This writes the device only after its physical confirmation.

Reset deletes all application records, including discoverable directories,
credentials, PIN/retry witnesses and configuration. It generates a new credential
key and setup generation, restores settings defaults, and clears RAM PIN tokens,
key agreements, failure blocks and continuation cursors. Old credential IDs
cannot authenticate against the new key. The device returns ready with PIN unset.
There is no default PIN. All hardware OTP, including the master root and
secure-boot key hash/policy, is retained. In insecure test builds the three
flash-emulated OTP records are also retained.

Cancellation before the transaction is committed makes no destructive change.
Once committed, reset runs to completion even if USB disconnects or cancels.
A lost acknowledgement can mean the reset succeeded: inspect INFO and the PIN
state before retrying. Reset must append its journal before deleting anything;
an entirely full or unreadable store can reject reset without changing state.
Cleanup scans the log per application key and can take time for large databases;
keep power connected until completion.

## Recovery

`recovery_required` keeps diagnostics reachable and disables credential services.
For readable, supported storage with a valid sealed root, the same local
release/three-second-hold/release gesture requests a **destructive factory reset**.
This recovery gesture has no ten-second boot restriction. It cannot recover lost
credentials or a forgotten PIN without erasing application data.

The coordinator first writes and verifies a root-encrypted transaction containing
the exact replacement journal, settings and credential key. Its presence blocks
all application access. Cleanup, state installation, completion, lifecycle and
metadata writes are idempotent. An interrupted reset reports
`reset_required / reset_interrupted`; boot automatically resumes that authenticated
transaction using the same replacement key, without another button confirmation.
An interrupted upgrade similarly reports `migration_required / upgrade_interrupted`.
Entropy/I/O failures leave services blocked; recognized transactions retry.

Malformed transactions, unknown formats, missing/invalid OTP roots, failed
authentication, unsupported downgrades and geometry mismatches stay blocked.
There is no speculative migration, automatic format, root regeneration or fuse
repair. Reinstall the matching supported firmware first. If the map/metadata is
unreadable, deliberate storage-only erase is an external recovery operation:
preserve hardware OTP and reinitialize with physical confirmation. A storage
erase also destroys flash-emulated test trust keys; it is not equivalent to the
implemented logical reset.

## Compatibility and downgrade policy

`init::lifecycle::upgrade` is a pure, explicit release table:

| Stored / running firmware | Action |
| --- | --- |
| `0.2.0` / `0.2.0` | Authenticate startup/lifecycle records; no boot-time rewrites |
| `0.1.0` / `0.2.0` | Validate existing initialization/completion, then migrate automatically |
| Newer stored version / older running version | Block downgrade |
| Other version combinations or invalid version text | Block until an explicit migration is implemented |

The `0.1.0` migration preserves the credential key, settings, credential records,
PIN/retry state, counters, extension seeds and OTP. It changes the startup state
marker from `DOOHCFG1` to `DOOHCFG2`, commits a matching completion witness and
records the new firmware version and geometry. The old firmware rejects the new
startup marker; it cannot silently use credentials after migration. Existing
credential formats `DOOHCR01/02/03` remain readable and are not bulk-rewritten.
Updating code requires extending the release table and update-image checker;
semver alone never establishes format compatibility.

The top-level metadata remains `DOOHICKEY` plus one firmware `version`. A
root-authenticated lifecycle record binds that same release version to the
storage boundary and flash capacity. Geometry must match after adoption; choose
the correct 4/16 MiB image for the initial migration, since old metadata did not
record geometry. Changing physical flash capacity is a separate migration.

Reserved coordinator keys are now `0xFFFFFE00..0xFFFFFE04`:

| Key | Content |
| --- | --- |
| `FE00` | Existing 57-byte initialization journal |
| `FE01` | Existing encrypted 100-byte settings/credential-key state, now v2 marker |
| `FE02` | Existing encrypted 72-byte completion witness |
| `FE03` | Root-encrypted 49-byte release/geometry header |
| `FE04` | Root-encrypted 207-byte reset/upgrade transaction; removed only after commit |

AEAD contexts and credential derivation labels remain stable. The transaction
holds the target header, operation, journal and replacement state. Firmware
version is never added to existing credential encryption keys or AAD.

## Firmware-only update procedure

Build and inspect the actual image without connecting a board:

```sh
cd firmware
cargo build --locked --release --target-dir target/4mb
python3 tools/check_update.py target/4mb/thumbv8m.main-none-eabihf/release/firmware --flash-mb 4

cargo build --locked --release --features flash-16mb --target-dir target/16mb
python3 tools/check_update.py target/16mb/thumbv8m.main-none-eabihf/release/firmware --flash-mb 16
```

The checker inspects ELF load addresses and an embedded build descriptor,
rejects storage overlap, wrong flash geometry and provisioning/test-OTP images,
and prints a SHA-256 manifest. It does not flash, sign or authenticate an image.
Verify physical capacity from the board/flash part, not its MCU package or
filename. INFO reports the compiled geometry; it does not measure the flash chip.

For a 4 MiB board in BOOTSEL, the existing single-slot installation path is:

```sh
picotool load -u -v -x -t elf target/4mb/thumbv8m.main-none-eabihf/release/firmware
```

Or use the debug probe with sector preservation and verification:

```sh
probe-rs download --chip RP235x --restore-unwritten --verify --reset \
  target/4mb/thumbv8m.main-none-eabihf/release/firmware
```

Substitute `target/16mb` for a 16 MiB device. Do not request chip erase, erase
storage, switch OTP backends, or flash a provisioning image during an update.
After reboot, INFO reports version/readiness; a recognized migration runs before
credential services resume. A same-version firmware-only reinstall retains data.

There is no A/B slot or automatic executable rollback. Power loss during firmware
programming may require BOOTSEL/SWD reinstall of the same or newer supported
image. Preserved storage then resumes any authenticated lifecycle transaction.
Boot diagnostics cannot run until a complete working executable is installed.
Secure-boot activation, signed artifacts and browser flashing remain separate
work; an already secured device must use an image authorized by its boot policy.

Logical deletion/key replacement is not physical secure erasure. Historical
encrypted state can remain in NOR flash, and replaying an entire old flash
snapshot can roll back both metadata and wrapped keys. This policy prevents
accidental incompatible use; cryptographic anti-rollback needs protected
monotonic state and an enforced signed boot/update chain.

Reset timing and physical interaction follow
[CTAP 2.3 section 6.6](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorReset).
