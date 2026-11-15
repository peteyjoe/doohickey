# Alpha release roadmap

Status: proposed implementation plan, researched against upstream sources on
2026-11-15. These tasks are not completed by this document. No release has been
published and no device has been provisioned as part of writing it.

The proposed alpha lets a tester install a release from the web app, explicitly
provision a supported device, finish setup, register and use test passkeys, and
install the next compatible release without losing credentials. Secure boot is
an explicit, separately qualified provisioning step. Use one normal application
image per flash capacity for both first installation and updates.

See [browser flashing and secure boot](web-flashing-and-secure-boot.md) for the
PicoFlash investigation, transport boundaries, signing/provisioning design, and
the browser implementation work. This roadmap is the release checklist.

## Current implementation

| Area | Present now | Still needed for the alpha |
| --- | --- | --- |
| Startup | Local button-confirmed setup/resume, durable settings and credential-key bundle, separate authenticated completion, startup ready/recovery states | Physical qualification, future settings/reset transactions and browser setup orchestration |
| Storage | Fixed 3 MiB boundary; byte-value map; metadata; encrypted single-value wrapper | Stable application key allocation/encodings, transaction/recovery policy, compatibility checks and migrations |
| Keys | TRNG-seeded CSPRNG; guarded OTP reader; opt-in hardware writes; separate insecure flash test backend | Qualified provisioning lifecycle, replaceable credential key under the immutable root, reset behavior |
| CTAP | Bounded codec, ES256 non-discoverable make/get, encrypted repository, durable counters, button UP and queued USB owner | Discoverable credentials, management, reset, extensions and full physical qualification |
| USB | FIDO HID transport and framed CDC ACM; public INFO including startup state | Readiness integration, restricted setup protocol, recovery/update entry workflow |
| Web app | Serial console, INFO display, text/hex traffic and tests | Installation/update wizard, WebUSB transport, artifact verification, setup/resume UX and WebAuthn test flow |
| Secure boot | Public-key-hash storage API, not activation | Signed artifact pipeline, complete policy/provisioning implementation, verified recovery and key-rotation plan |

The firmware currently cannot create or use passkeys. The web app currently
cannot flash firmware, enable secure boot, or initialize the device. Host tests
and successful cross-compilation do not establish those capabilities.

## Alpha scope and interface boundaries

Target desktop Chrome/Edge on the hardware/OS combinations actually tested.
Qualify RP2350 boards with both 4 MiB and 16 MiB flash; record board revision,
silicon stepping and flash part. Chip package and flash capacity are independent.
Do not infer external flash capacity from `rp235xa`/`rp235xb` or USB VID/PID.

The alpha's intended CTAP profile is the existing project's ES256,
discoverable/non-discoverable credentials, ClientPIN protocol 2, credential
management, credProtect and hmac-secret profile. Turn on advertised features only
after their algorithms and durable state work. A CTAP 2.3 target is not a FIDO
certification claim. Check applicable requirements in the
[CTAP 2.3 specification](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html).

Keep three browser paths distinct:

| Path | Purpose |
| --- | --- |
| WebUSB to ROM PICOBOOT in BOOTSEL | Install/recover an approved signed firmware artifact |
| Web Serial to application CDC ACM | Public device diagnostics and narrowly scoped, pre-operational device setup |
| WebAuthn through the platform's FIDO stack | Register/use test passkeys; platform handles the FIDO transport and UV prompts |

Use the platform's FIDO management UI or a trusted native CTAP tool where a
generic website cannot manage the PIN/reset operations. Do not implement them
by tunneling CTAP through CDC. Chrome blocks FIDO devices from general WebHID
access; see [Chrome's WebHID guidance](https://developer.chrome.com/docs/capabilities/hid).

Serial credential backups remain a desired later feature, with an unresolved
standards decision: CTAP 2.3 section 11.1 restricts exposing or changing FIDO
state through other interfaces. Encryption or a serial password alone does not
resolve that restriction. Keep credential export/import, PIN management and
credential enumeration off CDC in this alpha. Resolve the conformance and key
separation design before adding backups; document any deliberately nonconforming
experimental profile separately. See
[CTAP section 11.1](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html).

## Milestone 0: freeze the persistence and update contract

Do this before issuing an alpha that testers will expect to upgrade.

- [ ] Allocate and document application storage keys, record kinds, encodings,
  maximum sizes, ownership and deletion semantics. Preserve reserved metadata
  and OTP-test key ranges. Define behavior for records above the encrypted
  wrapper's 983-byte plaintext limit: bounded rejection, or a separately designed
  multi-record transaction; never silently truncate.
- [ ] Retain the existing top-level metadata contract: `DOOHICKEY` magic and
  **one firmware `version` field**. Do not add separate schema/layout versions.
  Maintain a compatibility/migration table keyed by firmware versions instead.
- [ ] Extend the coordinator's initial explicit `0.1.0` compatibility support into
  explicit decisions: known compatible, migration required, unsupported newer
  data, or unsupported downgrade. A compatible patch update should not require
  destructive initialization or a metadata write every boot.
- [ ] Keep cryptographic derivation labels, stored key identifiers, record-kind
  numbers and the encrypted wrapper's existing encoding/AAD stable. Firmware
  version must not become an encryption salt or part of existing record AAD.
- [ ] Define the root/credential key hierarchy below and freeze it before real
  credentials are issued.
- [ ] Decide the firmware update layout inside the first 3 MiB. The recommended
  first alpha uses the existing single application region with recoverable
  BOOTSEL reinstall. It does **not** promise automatic rollback after power loss.
  If A/B updates are required for the alpha, design and qualify them now within
  that region; they cannot take space from the promised user-storage partition.
- [ ] Decide whether the signing trust domain is project-controlled or
  owner-controlled. Proposed alpha: project-controlled release signing, with
  private keys kept out of the website/device. Document who can provide future
  updates and what happens if that signing service/key is lost.

**Acceptance:** an on-disk format/key map, version compatibility table, flash
write-range specification, trust policy and recovery contract are reviewed and
checked into the repository. Every other milestone uses those definitions.

### Permanent flash boundary

All ranges below are half-open; offsets are relative to flash, addresses are
the CPU/XIP mapping. They are not interchangeable in flash APIs.

| Region | Flash offsets | CPU/XIP addresses |
| --- | --- | --- |
| Firmware/update region, both builds | `0x00000000..0x00300000` | `0x10000000..0x10300000` |
| 4 MiB storage | `0x00300000..0x00400000` | `0x10300000..0x10400000` |
| 16 MiB storage | `0x00300000..0x01000000` | `0x10300000..0x11000000` |

The 4 MiB build has 1 MiB of storage; the 16 MiB build has 13 MiB. Both must
have the same application behavior and persistent encodings, differing only in
available storage. Board compatibility and security/build profiles are separate
artifact constraints, not consequences of choosing 4 versus 16 MiB.

Updater range checks must include all signed metadata, load segments, UF2 block
addresses if supported, padding and **rounded erase ranges**. No normal update
may erase/write at or beyond flash offset `0x00300000`, touch OTP, or run a full
chip erase. Validate the final packaged/signed image, not just the original ELF's
text size. The browser check prevents mistakes; enforce hardware/device policy
where available rather than treating JavaScript as an adversarial boundary.

## Milestone 1: durable initialization and reset

Implement under [firmware/src/init](../firmware/src/init/README.md), with one
owner of storage, RNG and application lifecycle. Startup inspection remains the
first application step after hardware initialization. Diagnostics must remain
reachable in setup/recovery; do not start credential services before validation.

The initial setup implementation and host failure tests now exist: physical
confirmation, validated root provisioning/seal resume, settings/key bundle and a
separate authenticated final commit. The items below remain release gates,
including physical qualification and the separate reset lifecycle. Base
initialization readiness does not mean the CTAP backend is operational.

- [ ] Specify persistent settings defaults and which values may be changed
  without a reset. Do not create a default PIN or serial-management password.
- [ ] Add explicit setup authorization using a deliberate physical button
  action with a timeout and release/debounce behavior. Opening a serial port or
  sending INFO must never authorize setup. Confirmation is local consent, not
  proof that a website or firmware image is trustworthy.
- [ ] Generate the unique 256-bit OTP root on-device using the existing
  hardware-TRNG-backed generator. Verify blankness and permission/lock preflight,
  program once, verify readback, seal and verify the intended page policy. Do
  not expose the root or use browser randomness for it.
- [ ] Generate a random, replaceable credential-encryption/wrapping key. Store
  it authenticated and encrypted under the OTP root, and use it for credential
  state and wrapped credential IDs. The immutable root must not make old
  credentials survive a logical authenticator reset.
- [ ] Persist default records and an authenticated completion record bound to
  the required settings and key generation. Read back and authenticate the
  required records before committing completion and entering an operational
  state. A single boolean or valid metadata header is insufficient.
- [ ] Specify a setup journal/commit sequence and safe checkpoints across power
  loss. Recover only recognized valid intermediate states, using explicit resume
  authorization where needed. Never rerun OTP programming over a partial record.
  Define whether an irrecoverable OTP slot requires a predesigned spare-slot
  policy or replacement hardware; do not improvise recovery fuse writes.
- [ ] Handle the existing-root/erased-flash case separately. Preserve OTP,
  require reinitialization authorization, and create fresh mutable application
  state. Missing metadata or failed decryption must not appear as an empty store.
- [ ] Implement CTAP reset on its specified FIDO path: invalidate all credentials,
  replace the mutable credential key and reset required PIN/token/state values
  while preserving the device's immutable root and secure-boot trust policy.
  Define physical confirmation and timing according to the selected CTAP profile.
- [ ] Document limits: log-structured flash may retain old records; restoring
  an old flash image may restore wrapped keys. If resisting flash rollback is
  required, implement a protected generation/monotonic-state design. Replacing
  a flash record alone is not physical secure deletion or anti-rollback.

**Acceptance:** reboot preserves the same root/settings/credential key; repeated
startup does not reprovision or rewrite unchanged defaults; interrupted setup
at every durable step is either safely resumable or clearly enters recovery;
reset invalidates both discoverable credentials and old wrapped credential IDs.

## Milestone 2: make the CTAP profile operational

- [x] Implement bounded canonical CBOR/COSE input decoding and development
  getInfo output with explicit length, nesting, collection, duplicate-key and
  malformed-input policy. Credential response encoders follow with handlers.
- [x] Connect a single stateful authenticator owner to the existing HID backend
  and typed handlers. Integrate real user presence, deadlines, keepalives and
  cancellation at safe points; do not cancel partially completed flash writes.
- [ ] Implement the selected command algorithms, actual getInfo capabilities,
  credential creation/lookup/deletion, enumeration and continuations.
- [ ] Persist credential records, PIN verification state/retry counters and
  required counter/extension state across resets and updates. Storage errors
  must not unset a PIN, reset retry limits or regenerate extension secrets.
- [x] Implement protocol-2 ClientPIN, durable retries, token scope, lifetime and RP-binding rules; keep these
  permissions separate from vendor lifecycle/setup authorization.
- [ ] Choose/document attestation behavior and AAGUID for the alpha. Advertise
  only implemented options/extensions and address the complete selected profile,
  not only the commands used by a single browser demo.
- [x] Gate application readiness on initialization and required record checks;
  expose real transport/backend availability in diagnostics.

**Acceptance:** register and authenticate a test credential, power-cycle, update
firmware, and authenticate the original credential again. Exercise discoverable
and allow-list flows, PIN failures/retry persistence, credential management,
supported extensions, cancellation, full storage and malformed requests using an
independent CTAP client and target browser/platform combinations.

## Milestone 3: qualify signing and secure provisioning

- [ ] Pin release tools and preserve reproducible build inputs. Produce separate
  normal 4 MiB and 16 MiB artifacts plus an authenticated release manifest with
  capacity, board/silicon compatibility, version compatibility, exact addresses,
  hashes, sizes, security profile and required signing-key identity.
- [ ] Build and validate ROM-signed artifacts off-device using the reviewed
  project signing pipeline. Store/backup signing keys outside the repository,
  browser bundle and ordinary build logs. A signed manifest is useful for
  distribution; the ROM-recognized image signature is separately required.
- [ ] Implement a narrow, audited provisioning workflow for the full secure-boot
  policy. The existing OTP API writes BOOTKEY0's hash but does not activate it,
  enable secure boot, lock all required paths or establish release security.
- [ ] Validate signed boot and recovery on sacrificial hardware before any
  irreversible closure. Root-page locking, key validity/revocation, secure boot,
  debug restrictions, bootloader OTP permissions, alternate boot paths and any
  partition protection must be reviewed as one policy.
- [ ] Prove that the selected policy permits future authenticated recovery and
  browser updates while denying root readout and unauthorized execution. Keep
  the required PICOBOOT recovery interface available if it is the update path.
- [ ] Plan signing-key rotation, spare key slots, revocation and rollback-floor
  policy before consuming irreversible OTP settings. Do not advance a hardware
  rollback floor for every alpha patch or before a viable recovery image exists.
- [ ] Keep `insecure-test-otp` artifacts isolated and explicitly marked; never
  offer them as the normal/secured alpha. A debug-enabled development build must
  not be described as protecting OTP against a debugger.

**Acceptance:** the approved signed image boots, modified/unsigned/wrong-key
images fail to execute, and a secured device can still recover and install the
next approved image with original credentials intact. Test actual policy readback
after reboot. An image filename or a nonempty boot-key hash is not evidence that
secure boot is enabled.

## Milestone 4: browser installation, setup and update

Implement the detailed tasks in
[web-flashing-and-secure-boot.md](web-flashing-and-secure-boot.md). Proposed UI:

```text
Install: choose supported board -> verify release -> BOOTSEL WebUSB connection
         -> flash/verify signed image -> reconnect application serial
         -> inspect device -> explicitly provision security if needed
         -> explicitly initialize device -> FIDO enrollment/test

Update:  inspect running device -> check compatibility -> confirm update
         -> release serial -> enter BOOTSEL -> select bootloader device
         -> flash/verify signed image -> reconnect -> validate/migrate -> verify

Recovery: identify actual boot/security state -> reinstall compatible signed
          image -> inspect -> explicit repair/resume if supported
```

- [ ] Implement the release/artifact verifier and firmware-only write planner
  before exposing a Flash button. Use a reviewed, pinned PicoFlash transport
  behind that planner; do not expose arbitrary addresses or OTP writes.
- [ ] Add a setup wizard that displays initialization reason and can resume only
  validated setup states. Secrets stay on-device. First-use vendor setup is
  unavailable after operation begins; normal FIDO state changes use FIDO paths.
- [ ] Make secure-boot provisioning a separate explicit wizard stage with a
  plan summary and physical confirmation, then report actual verified results.
  If that browser provisioning implementation is not yet qualified, label it
  unavailable and direct testers to the validated native workflow. Do not claim
  the full browser secure-provisioning milestone complete in that case.
- [ ] Support manual BOOTSEL first. A later application reboot-to-update command
  needs appropriate authorization/physical presence and must drain storage and
  close sessions before reboot. Existing CDC does not implement this command.
- [ ] Add a WebAuthn test page with proper challenge/origin/RP/public-key/signature
  verification, rather than equating a resolved JavaScript promise with a tested
  authenticator. Label this a test RP; never upload device secrets.
- [ ] Handle separate WebUSB and Web Serial permissions, re-enumeration and
  cancellation. A remembered USB grant, VID/PID or serial number is not
  cryptographic device identity. Do not silently provision a different board.

**Acceptance:** a new tester follows the documented flow on a supported OS,
secures/initializes the board, uses a test passkey, updates, and uses that same
passkey again. Error/cancel/disconnect states provide a tested recovery route.

## Milestone 5: alpha qualification and release

Record completed physical checks in the [hardware validation log](hardware-validation.md).
The initial 4 MiB emulator-backed reset/USB baseline is recorded there; the
remaining qualification gates below still need their own evidence.

Record exact artifacts, hardware, browser/OS versions, procedures and results.
Build logs and simulated devices are separate from physical test evidence.

| Test | Required evidence |
| --- | --- |
| Fresh install, both flash capacities | Correct geometry/profile selected; explicit setup; no host-visible root; actual security readback |
| Boot/update persistence | Same preexisting credential works after reboot and N -> N+1 update; defaults/PIN/retries/extension outputs preserved as specified |
| Migration | Compatible no-op update, interrupted migration, invalid/newer version, permitted and rejected downgrades |
| Range enforcement | Out-of-range segments, boundary-crossing erase padding, overflow, malformed UF2 if accepted, wrong capacity/board/profile all rejected before mutation |
| Signing | Wrong key, modified payload/manifest, unsigned image, key-rotation/recovery behavior |
| Interruption | USB removal/power loss during erase, program, setup, OTP/lock stages and migration; documented recoverability and no silent reset |
| Reset | Required physical/timing controls; previous credentials and IDs invalid; OTP root and boot trust retained |
| Browser/driver behavior | Claimed Windows/macOS/Linux combinations, canceled choosers, device switching, interface ownership and reconnect |
| Interface boundary | CDC cannot expose/change FIDO state or secrets; setup/provision/reboot entry points obey lifecycle and consent rules |

For A/B designs, add failed trial boot, watchdog fallback, confirmation ordering,
rollback-floor changes and data compatibility with the fallback image. Firmware
rollback is not sufficient if the trial already destructively migrated storage.

Suggested automated checks, from the repository root's development shell:

```sh
cd firmware
cargo fmt --all --check
cargo test --locked -p doohickey-crypto --target x86_64-unknown-linux-gnu
cargo clippy --locked -p doohickey-crypto --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
cargo clippy --locked --bin firmware -- -D warnings
cargo build --locked --release --target-dir target/4mb
cargo build --locked --release --features flash-16mb --target-dir target/16mb
cargo build --locked --release --features insecure-test-otp --target-dir target/otp-test-4mb
cargo build --locked --release --features flash-16mb,insecure-test-otp --target-dir target/otp-test-16mb
```

Use the appropriate host Rust target on macOS/ARM Linux. Also check the explicit
hardware provisioning build in an isolated target directory, and retain the
compile-time rejection of combining the two OTP features. These commands only
test/build; they do not establish signing, provisioning or physical behavior.

Continuing from `firmware/`, run the web checks:

```sh
cd ../website-test
npm ci
npm test
npm run typecheck
npm run build
npm run test:e2e
```

If starting from the repository root, use `cd website-test` instead.
Install/configure Playwright's browser as described in the
[web README](../website-test/README.md). Expand CI to include the new updater,
compatibility and setup tests before shipping those features.

- [ ] Assign a prerelease version/tag such as `0.1.0-alpha.1` after deciding the
  persistence contract. Record the commit, toolchain and dependency locks.
- [ ] Publish approved artifacts, authenticated manifest, checksums, public
  verification keys/fingerprints, compatibility table, recovery instructions and
  release notes together. Record the matching web-app version and supported
  serial/setup protocol versions. Publish no private signing material.
- [ ] Preserve prior releases and compatible signed recovery artifacts; announce
  which upgrades/downgrades are supported and whether migrations are reversible.
- [ ] Document the alpha's limitations, threat model, backup unavailability,
  debug versus secured profiles, known issues and absence of certification.
  Instruct testers to use test accounts or independent recovery methods.
- [ ] Review open-source notices for distributed dependencies and freeze the
  tested website assets and firmware artifacts for that release.
- [ ] Release only after the claimed capability gates above have evidence. A
  transport-only preview can ship earlier under that explicit description; it
  is not the working-authenticator alpha defined here.

## Compatibility rules for every later release

An update preserves OTP root and boot trust; application data survives outside
the firmware region. Read the stored firmware version before migration and
update it only after a verified durable transition. Keep old records readable
until a resumable migration commits. Never use version mismatch, bad metadata,
authentication failure or missing settings as permission to format.

A firmware-only reinstall can repair damaged code; it cannot recover erased
credentials or a lost credential key. An encrypted flash snapshot wrapped under
one device's root is not automatically portable to a replacement device. Do not
promise backup/restore or flash-rollback resistance until those features have
their own implemented and qualified design.
