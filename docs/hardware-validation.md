# Physical validation log

## 2026-11-15: initialization and USB baseline

Tested the user's connected RP2350 through a Raspberry Pi Debugprobe on Pico
(CMSIS-DAP/SWD), plus the board's native USB connection. The worktree is not
committed; identify the tested image by the ELF digest below.

| Property | Observed value |
| --- | --- |
| Firmware version | `0.1.0` |
| Reported flash build | 4 MiB / `4194304` bytes |
| OTP backend | `insecure-test-otp` (flash emulator) |
| Initialization before reset | `ready / none` |
| Initialization after SWD reset | `ready / none` |
| CTAP/authentication backend readiness | Both false, as expected |
| ELF | `firmware/target/otp-test-4mb/thumbv8m.main-none-eabihf/release/firmware` |
| ELF SHA-256 | `610662662911cc6990b456e3e7da5379a46a3ea01e9ff047e01e575e424db49d` |

The reported flash size is a firmware build constant, not an independent
measurement of the external flash chip's physical capacity.

Checks completed:

- SWD discovery found the RP235x CoreSight components and Cortex-M33 cores.
  Generic automatic chip identification did not succeed; commands explicitly
  targeting `RP235x` succeeded.
- SWD could read the firmware's public vector-table words.
- Native CDC ACM returned valid framed INFO with initialization ready.
- `probe-rs reset --chip RP235x` succeeded; a subsequent fresh serial connection
  returned initialization ready again.
- `probe-rs verify --chip RP235x` matched the local ELF against programmed
  firmware. This was verification, not a firmware download.
- Native HID INIT echoed the nonce, allocated a valid CID and reported the
  expected protocol/capabilities.
- A fragmented 200-byte HID PING round-tripped.
- CBOR transport of the getInfo command returned OperationDenied (`0x27`),
  as expected from the current unavailable CTAP backend.
- A final serial INFO request still reported initialization ready.

No erase, firmware download, OTP provisioning, secure-boot activation, credential
creation/deletion or reset-of-user-state command was issued. GPIO confirmation
was not simulated or bypassed. The board was left running its existing firmware.
Serial/HID checks used bounded standard-library Linux I/O and the existing
`firmware/tools/usb_smoke.py` framing helpers.

This establishes authenticated initialization loading across a probe-triggered
reset and a physical USB transport baseline. It does not qualify fresh setup,
the physical button sequence, power removal, interrupted writes, an actual
firmware upgrade, 16 MiB hardware, hardware OTP, secure boot, CTAP credentials,
or byte-for-byte storage preservation. Normal firmware storage reads retain the
log library's existing repair behavior.

The follow-up below validates discovery and a firmware update. Keep the
remaining physical initialization checks in the
[alpha qualification plan](alpha-roadmap.md).

## 2026-11-15: bounded CBOR and getInfo firmware update

Updated the same connected board using its existing 4 MiB `insecure-test-otp`
build policy. Public serial INFO reported `ready / none` immediately before
and after the update, with `ctap_ready=false` and `authentication_ready=false`.
No setup confirmation or reinitialization was requested.

| Property | Observed value |
| --- | --- |
| Firmware version | `0.1.0` (unreleased development build) |
| ELF | `firmware/target/otp-test-4mb/thumbv8m.main-none-eabihf/release/firmware` |
| ELF SHA-256 | `96cfafd3192890ba4f728ba09a88937f35b8eab0ee281978ee0c0b3705c16066` |
| Highest programmed segment end (exclusive) | `0x10038c3c` |
| Storage start | `0x10300000` |

Inspected every nonempty ELF LOAD segment before download. Programmed addresses
were confined below storage. Used sector programming, restoration of unwritten
sector bytes, post-program verification and reset:

```sh
cd firmware
probe-rs download --chip RP235x --probe 2e8a:000c:74772EA5628CC51A \
  --disable-progressbars --restore-unwritten --verify --reset \
  target/otp-test-4mb/thumbv8m.main-none-eabihf/release/firmware
```

Native HID checks passed using the repository smoke tool's wire fixtures:

- INIT nonce/CID/protocol/capabilities and fragmented 200-byte PING.
- getInfo success and exact canonical response: development `FIDO_2_0`,
  AAGUID `DOOHICKEY-DEV001`, rk/up/plat false, maxMsgSize 1024, USB transport,
  and no advertised PIN, UV or extensions.
- Unexpected getInfo parameters: InvalidLength (`0x03`).
- Duplicate map keys, five levels of containers, or a tag inside an unknown
  field: InvalidCbor (`0x12`).
- A 33-element unknown collection: RequestTooLarge (`0x39`).
- Missing makeCredential fields: MissingParameter (`0x14`).
- Wrong top-level type: CborUnexpectedType (`0x11`).
- Unknown opcode and structurally valid unfinished getAssertion (including a
  fragmented request with a 256-byte unknown field): InvalidCommand (`0x01`).
- A subsequent getInfo still succeeded, followed by ready serial INFO.

All 95 host tests, host/embedded Clippy with warnings denied, and release builds
for both 4/16 MiB with hardware/default and emulated OTP policies passed.
Formatting and whitespace checks passed. Builds retain the existing dependency
future-compatibility notice for proc-macro-error2.

This validates development discovery and authenticated initialization loading
after an actual firmware update with the same persistent record format. It
does not establish byte-for-byte storage preservation, interrupted-update or
power-loss behavior, 16 MiB hardware, real OTP provisioning, secure boot, or
credential/PIN operation. No bulk erase, hardware OTP or secure-boot programming,
credential changes, or user-state reset was performed. The board is running
the new development firmware. The next implementation step is the stateful
credential repository and makeCredential/getAssertion algorithms.
