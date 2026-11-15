# Composite USB

The main firmware now runs Embassy USB 0.6 with the RP2350 USB driver. One
composite device exposes three interfaces, grouped into two functions:

| Interface | Class | Purpose |
| --- | --- | --- |
| 0 | HID, subclass/protocol 0 | FIDO usage page `0xF1D0`, usage 1; interrupt IN/OUT |
| 1 | CDC ACM communication | Serial control and notification endpoint |
| 2 | CDC data | Serial bulk IN/OUT |

The device uses IADs and device class/subclass/protocol `EF/02/01`. Endpoint 0,
HID reports, and CDC data packets are 64 bytes; HID polling interval is 5 ms.
The builder owns descriptor buffers and class state inside the pinned USB
future. USB control, HID and CDC run concurrently with the local initialization
confirmation loop after startup inspection. Inspection never generates keys;
explicit GPIO 23 confirmation can initialize eligible devices using the selected
OTP backend/build policy. See [durable initialization](../init/README.md).

VID/PID **`c0de:d001` are development placeholders**, centralized in `mod.rs`;
replace them with assigned identifiers for distribution. No per-device serial
number is advertised yet. RTT/defmt stays on the debug probe and is not mixed
into the CDC binary stream.

## CTAPHID

`ctaphid.rs` implements INIT allocation/resynchronization, PING echo, CBOR
transport, cooperative CANCEL, KEEPALIVE and ERROR. Messages are reassembled
with a 1024-byte limit, ordered continuation packets and a 3-second inter-packet
timeout. Replies are fragmented into zero-padded reports. Other channels receive
busy errors during a transaction; stray continuation packets are ignored.
INIT reports CTAPHID version 2, the Cargo firmware version components, and
capabilities `0x0c` (CBOR framing and no CTAP1/U2F MSG). Optional WINK/LOCK are
not advertised. Channels are unique for this firmware boot and invalidated by
USB reset/unconfiguration.

Main uses `cbor::AuthenticatorBackend` and the bounded exchange with the single
application/storage owner. The development FIDO_2_0 profile supports ES256
registration, packed self-attestation and allow-list assertions with real UP.
PIN/UV, discoverable credentials, reset, credential management and extensions
remain unavailable. `ctap_ready` reports this limited profile; serial
`authentication_ready` remains false. See the [credential milestone guide](../../../docs/credential-milestone.md)
for button behavior, persistence and the independent client test.

`Backend::start` receives `command_byte || CBOR_parameters`; it must copy/queue
the input before returning if it needs to retain the request. The discovery
adapter decodes synchronously and retains no input references. `poll` returns a response CBOR body or a CTAP error,
or Pending with Processing/UserPresence progress. The transport supplies the
leading CTAP status byte and keepalives every 100 ms or on progress changes.
Implement the adapter with a single authenticator/repository owner; it must not
block the USB task. CANCEL is a cooperative signal, not a dropped operation
future. Resynchronization and USB disconnect drain outstanding work before reuse
and discard obsolete replies. Clear appropriate continuation state as part of
the backend's resynchronize/disconnected callbacks.

## CDC serial

USB packets are not application message boundaries. Both directions use:

```text
length: u16 big-endian || payload[length]
```

Payload length is 1..=1040 bytes. The incremental decoder handles split headers,
split payloads and multiple frames per USB packet. A complete frame must arrive
within 2 seconds from its first header byte. Invalid lengths/timeouts quarantine
the session; close and reopen the port to reset framing. DTR must be asserted.
Bus reset, unconfiguration, or CDC line-control changes clear partial frames and
invoke the serial handler's disconnected callback. Queued endpoint writes check
their connection generation on every poll, including rapid close/reopen events.
Clients should discard buffered input when opening a new session.

The current public handler accepts exactly `INFO` (`00 04 49 4e 46 4f` on the
wire) and returns framed UTF-8 JSON containing product, firmware version, selected
flash capacity and development/readiness flags. Startup inspection also adds
`initialization` and `initialization_reason`; see [the coordinator](../init/README.md).
These are diagnostic states, not permission to provision or reset. Other frames return framed
`ERR AUTH_UNAVAILABLE`; it exposes no FIDO credential, PIN or pairing state.
Framing errors return a framed error when possible. Plain terminal input is not
this binary protocol, so use the smoke tool or a length-framed client.

The 1040-byte limit can carry the existing Noise transport records, but **Noise
pairing/authentication is not wired into CDC yet**. Do not send production backup
data. A future management::Handler must maintain explicit handshake/session
state, decrypt/authenticate before interpreting sensitive commands, and discard
keys/counters/authorization on disconnect. A length prefix alone authenticates
nothing. Standard CTAP requests stay on FIDO HID; CDC is not a second CTAP path.

## Build and test

```sh
cd firmware
DEFMT_LOG=info cargo run --release --target-dir target/4mb
# For 16 MiB: add --features flash-16mb and use target/16mb.
```

After flashing, connect the board's **native USB data port** to the host. The
debug probe's own USB port carries SWD/RTT, not these device interfaces. On Linux,
expect one FIDO hidraw interface and one `/dev/ttyACM*`; macOS uses
`/dev/cu.usbmodem*`, Windows a COM port with native CDC ACM/HID drivers.

Create a host test environment and run the smoke tool from `firmware/`:

```sh
python3 -m venv /tmp/doohickey-usb-test
/tmp/doohickey-usb-test/bin/pip install hidapi pyserial
/tmp/doohickey-usb-test/bin/python tools/usb_smoke.py --serial /dev/ttyACM0
```

Use `--skip-hid --serial PORT` for CDC only, or omit `--serial` for HID only.
The tool verifies INIT nonce/CID/capabilities, a fragmented 200-byte PING,
the canonical development getInfo response, malformed/unsupported request errors,
subsequent recovery, and public serial information. It does not modify flash or
OTP. Install narrowly scoped Linux hidraw/tty rules as described in the root
README, and substitute the actual development VID/PID. WSL also needs the native
USB device attached via usbipd, separately from the debug probe.

Host tests use the actual hardware-independent engines, including malformed
reports, arbitration, timeout recovery, cancellation/resync, disconnected
backends, stream framing, and connection-generation checks. They do not prove
physical USB enumeration or OS-driver behavior; run the on-device smoke tool.

```sh
cargo test -p doohickey-crypto --test usb --target x86_64-unknown-linux-gnu
```

References: [Embassy USB 0.6](https://docs.embassy.dev/embassy-usb/0.6.0/default/),
[CTAP 2.3 section 11.2](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html).
