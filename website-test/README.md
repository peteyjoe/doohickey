# DOOHICKEY Serial Lab

A Nuxt 4 / Nuxt UI application for testing the firmware's native USB CDC ACM
interface through Web Serial. It includes connection controls, public device
information, text/hex requests and traffic, response timing, and JSON log export.
All displayed device information comes from the connected device. There is no
demo connection in the application.

## Planned installer and setup flow

Browser installation, signed updates, secure-boot provisioning and device setup
are documented in the [alpha roadmap](../docs/alpha-roadmap.md) and
[browser flashing design](../docs/web-flashing-and-secure-boot.md). They are not
implemented in this console yet. The proposed flow uses WebUSB/PICOBOOT in
BOOTSEL for firmware installation, then Web Serial for device diagnostics and
restricted setup, with FIDO operations kept on the platform's FIDO path.

## Run

Use the repository's `nix develop` shell (Node.js 26 and npm), or a current Node.js
26 installation:

```bash
cd website-test
npm ci
npm run dev
```

Open **http://localhost:3000** in desktop Chrome or Edge. Web Serial requires a
secure context: localhost works for development; a remotely hosted instance needs
HTTPS. The page displays instructions and disables connection if Web Serial is
unavailable. A responsive layout is included, but a mobile browser is not the
intended hardware test environment.

## Connect to the board

1. Run the firmware with its USB composite device enabled, then plug the board's
   **native USB data connector** into the computer running the browser. The debug
   probe's USB connector is a separate interface. BOOTSEL mode is for flashing;
   exit it and run the firmware before connecting here.
2. Close other programs using this serial interface, including serial monitors
   and `usb_smoke.py`.
3. Click **Connect device** and select the DOOHICKEY serial port in the browser's
   permission picker. The default filter matches the firmware's development
   VID/PID `c0de:d001`. Enable **Show all serial ports** if you change these IDs.
4. Leave **Read INFO on connect** enabled. The panel should show the actual
   firmware version, 4 or 16 MiB flash capacity, CTAP/authentication readiness,
   and whether OTP uses hardware or the insecure flash test backend.
5. Send `INFO` again with the quick command, refresh button, or message composer.
   In **Hex** input mode enter `49 4e 46 4f`. Do **not** enter the length header;
   the application adds it automatically.

The client asserts **DTR**, which the firmware requires. The baud rate is passed
as CDC line coding; this native USB transport does not use a physical UART clock.
The HID CTAP interface is separate and is not exercised by this application.

When running Nuxt in WSL, open localhost in the Windows browser and keep the USB
device attached to Windows so that browser can access it. If a device is passed
through to WSL, it must be returned to Windows before the Windows browser can use
it. On Linux, the browser's user must have permission to open the serial device;
check the device's group and your distribution's serial-port permissions if the
picker works but opening fails.

## Firmware protocol

Every request and response is one frame:

```text
[2-byte unsigned big-endian payload length][1–1040 payload bytes]
INFO request: 00 04 49 4e 46 4f
```

USB reads may contain partial or multiple frames. The decoder handles both and
rejects zero or oversized lengths. Only one request is outstanding at a time
because this protocol does not carry request IDs.

The **current firmware only implements the exact ASCII command `INFO`**, returning
a UTF-8 JSON object with `product`, `firmware`, `flash_bytes`, `ctap_ready`,
`authentication_ready`, `insecure_test_otp`, `initialization`, and
`initialization_reason`. The current device-details panel shows the basic fields;
the full response, including startup state, is visible in the traffic monitor.
Other payloads produce
`ERR AUTH_UNAVAILABLE`. Sending `BACKUP`, for example, tests that rejection path;
it does not create a backup. Authentication, encrypted sessions, and credential
backup/restore are not yet wired into the firmware's serial handler.

The UI adds framing but otherwise sends the entered payload as-is: text uses
UTF-8 without an appended newline, and hex requires complete byte pairs. The hex
traffic display includes the length header, while byte counts distinguish
payload size from total wire bytes.

An incomplete response frame times out after 2 seconds. A request without a
response times out after 3 seconds. Malformed frames, firmware framing errors,
and response timeouts close the connection. Click **Connect device** again to
start a fresh session and avoid confusing a late response with another request.
Unplugging also releases the connection; reconnect the cable and select the port
again. Page teardown releases stream locks and closes the port.

Traffic stays in memory in the current tab, capped at the latest 250 entries.
**Export log** explicitly downloads those entries as JSON; **Clear log** removes
them without resetting session counters. Nothing is stored in local storage or
uploaded by the console. Exported logs contain the transmitted payloads.

## Validate and build

```bash
npm test
npm run typecheck
npm run build
npm run preview
```

The unit tests exercise framing boundaries, fragmented/coalesced input,
timeouts, INFO validation, DTR, single-request handling, stream cleanup, failure
recovery, and disconnect/open races. They use Node's built-in test runner.
TypeScript is kept on version 6 because the current Vue type checker does not
support TypeScript 7.

Browser tests use the installed Nuxt test utilities and Playwright. Install a
browser once, then run:

```bash
npx playwright install chromium
npm run test:e2e
```

The browser suite builds the application and starts a local production server
on port 3111. It tests INFO, text/hex input, firmware rejection, disconnect and
unplug recovery, malformed responses, JSON export, unsupported browsers, and
mobile layout. It replaces `navigator.serial` **only inside the tests**, using
the firmware's wire format. A successful browser suite does not verify the
physical board or operating-system USB drivers.

On NixOS, use a Nix-provided Chromium executable instead of Playwright's downloaded
browser:

```bash
PLAYWRIGHT_CHROMIUM_EXECUTABLE="$(command -v chromium)" npm run test:e2e
```

Chromium must be available in that shell. UI code is in `app/app.vue`, connection
lifecycle in `app/utils/webSerial.ts`, wire framing in
`app/utils/serialProtocol.ts`, and reactive state/logging in
`app/composables/useSerialConsole.ts`.
