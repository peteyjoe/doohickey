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

Next implementation milestone: bounded CBOR/COSE handling and a genuine getInfo
response with truthful capabilities, then the stateful credential algorithms.
Keep firmware-update persistence and the remaining physical initialization
checks in the [alpha qualification plan](alpha-roadmap.md).
