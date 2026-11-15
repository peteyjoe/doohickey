# RP2350 FIDO2 development

This flake provides an Embassy/Rust firmware toolchain and Node.js 26 LTS with
npm for Nuxt. It supports Linux (`x86_64-linux`, `aarch64-linux`), including
**WSL 2**, and macOS on **Apple Silicon** (`aarch64-darwin`) and **Intel**
(`x86_64-darwin`). The Rust overlay follows the main nixpkgs input.

Linux and Apple Silicon use the pinned nixos-unstable input. Intel Macs use a
separate pinned `nixpkgs-26.05-darwin` input because
[nixpkgs 26.11 dropped Intel macOS support](https://nixos.org/manual/nixpkgs/unstable/release-notes#x86_64-darwin-26.11).
That release receives security fixes through the end of 2026; Intel support
will need revisiting afterward. Host package versions can differ between these
inputs; all hosts use the same Rust overlay and embedded target.

## Alpha release and upgrade plan

The [alpha roadmap](docs/alpha-roadmap.md) tracks the work needed for a usable
authenticator: durable initialization, CTAP algorithms, signed releases,
browser installation/setup, persistence across updates and hardware qualification.
The [browser flashing and secure-boot design](docs/web-flashing-and-secure-boot.md)
records the PicoFlash investigation and the proposed WebUSB/Web Serial workflow.
Browser flashing, secure-boot activation and application setup are planned work;
the current web app is a serial test console.

## Install Nix

On NixOS, Nix is already installed. On other Linux distributions with systemd,
install Nix using the [official multi-user installer](https://nix.dev/manual/nix/latest/installation/installing-binary.html):

```sh
sh <(curl -L https://nixos.org/nix/install) --daemon
```

Run this from Bash as your normal user; the installer requests sudo when needed.
Open a new terminal afterward. For macOS and Windows, follow the setup below.

### macOS

Install Apple's Command Line Tools if they are not already installed (this also
provides Git for cloning the repository):

```sh
xcode-select --install
```

In Terminal, install Nix using the same official multi-user installer:

```sh
sh <(curl -L https://nixos.org/nix/install) --daemon
```

Open a new terminal, enter your checkout, and use the `nix develop` command below.
On Apple Silicon, use a native ARM terminal rather than a terminal running under
Rosetta. Nix selects the shell for your host automatically. No nix-darwin or
Homebrew setup is required for this environment.

macOS does not use udev; skip the Linux permissions section. A Raspberry Pi Debug
Probe (CMSIS-DAP) needs no extra driver according to the
[probe-rs setup guide](https://probe.rs/docs/getting-started/probe-setup/).
If macOS asks to allow a USB accessory, allow it. Check the connection with
`probe-rs list` for a debug probe or `picotool info` for a board in BOOTSEL mode.
For USB CDC serial, find the port with `ls /dev/cu.usb*` and run, for example,
`tio /dev/cu.usbmodem1234` using your actual port name. Close other programs using
the device before flashing or opening it from Chrome.

### Windows with WSL 2

Use a Linux distribution in **WSL 2**, rather than running Nix in PowerShell or
WSL 1. In an administrator PowerShell, install/update WSL and check the distro's
version:

```powershell
wsl --install -d Ubuntu
wsl --update
wsl --list --verbose
```

Restart Windows if requested and finish Ubuntu's first-run user setup. For an
existing WSL 1 distro, convert it with `wsl --set-version Ubuntu 2` (substitute
its actual name).

Inside Ubuntu, check that systemd is running with `systemctl status`. If needed,
merge this into `/etc/wsl.conf`, preserving existing settings:

```ini
[boot]
systemd=true
```

Run `wsl --shutdown` in PowerShell, then reopen Ubuntu. See Microsoft's
[systemd instructions](https://learn.microsoft.com/en-us/windows/wsl/systemd).
Install Git, curl, and certificates inside Ubuntu if missing:

```sh
sudo apt update
sudo apt install git curl ca-certificates
```

Run the Linux Nix installer above **inside Ubuntu**, open a new Ubuntu terminal,
and clone this repository under your Linux home directory (for example,
`~/src/`), avoiding `/mnt/c/` for build performance. Enter the checkout and use
`nix develop` below. WSL uses the Linux shell for its architecture.

Building firmware and running Nuxt do not require USB forwarding. To flash or
use serial/debug tools inside WSL, follow Microsoft's
[USB forwarding guide](https://learn.microsoft.com/en-us/windows/wsl/connect-usb).
With usbipd-win 5 or newer, install and share the device from an administrator
PowerShell (replace `4-4` with its bus ID):

```powershell
winget install --interactive --exact dorssel.usbipd-win
usbipd list
usbipd bind --busid 4-4
```

Keep Ubuntu open. Attach the shared device from a normal PowerShell:

```powershell
usbipd attach --wsl --busid 4-4
```

Inside the Nix shell in Ubuntu, verify it with `lsusb`, then use `probe-rs list`
or `picotool info`. Follow the Linux device permissions section below as well;
forwarding alone does not grant your Linux user access. Ensure udev is running
with `systemctl status systemd-udevd`; if inactive, start it with
`sudo systemctl start systemd-udevd`. Use a device group for headless WSL sessions
where `uaccess` does not grant access.

Reattach after unplugging or rebooting into BOOTSEL; the bus ID or USB identity
may change, requiring another bind. To return the device to Windows:

```powershell
usbipd detach --busid 4-4
```

An attached device is unavailable to Windows apps, including Chrome/Edge. Detach
it before using a Windows browser for WebUSB, Web Serial, or WebAuthn. You can
run Nuxt in WSL and open `http://localhost:3000` in the Windows browser; stop WSL
serial/debug tools before switching device ownership.

## Enter the environment

Enable `nix-command` and `flakes` in your Nix configuration, then run:

```sh
nix develop
```

Or enable those features for just this invocation:

```sh
nix --extra-experimental-features 'nix-command flakes' develop
```

Commit `flake.nix` and `flake.lock` together. The lock pins the Rust toolchain and
all Nix packages; `nix flake update` intentionally updates the inputs. In a Git
checkout, new flake files must be added to Git before Nix can see them.

The shell includes rustc, Cargo, rustfmt, Clippy, rust-analyzer, Rust sources,
LLVM tools, cargo-binutils, probe-rs (including cargo-embed), picotool, Raspberry
Pi's OpenOCD fork, multi-target GDB, tio, lsusb, native build tools, and libraries
for host USB/HID/OpenSSL programs. No rustup installation is needed. Start your
editor from the shell to make these tools available to it.

## Firmware

The installed embedded target is `thumbv8m.main-none-eabihf`, for the RP2350's
Arm Cortex-M33 cores, matching [Embassy's RP235x configuration](https://github.com/embassy-rs/embassy/blob/main/examples/rp235x/.cargo/config.toml).
This environment assumes Arm firmware; the RP2350's alternative RISC-V cores
would need a different target and firmware setup. Embassy is a Cargo dependency
managed in `firmware/Cargo.toml`, rather than a Nix package.

The `firmware/` crate runs the [initialization coordinator](firmware/src/init/README.md)
after hardware setup, then starts a composite USB device with FIDO HID transport
and CDC ACM serial. It reports startup status through RTT/defmt and serial INFO.
ES256 allow-list and discoverable credential flows, including PIN-based UV,
are implemented. Serial authentication still needs its application backend. Eligible device setup uses a fresh three-second hold and release on
GPIO 23 (active low, pull-up). It verifies durable settings, credential key and
completion records before reporting base initialization ready. Real root writes
additionally require the explicit `otp-provisioning` feature; use
`insecure-test-otp` for flash-only development. Secure boot remains separate.

The chip and flash defaults remain RP2350A with 4 MiB flash. Check the chip
feature (`rp235xa`) in `firmware/Cargo.toml`, the flash-size build option below,
and the button pin in `firmware/src/main.rs` against your board.
Use `rp235xb` instead for an RP2350B. A non-wireless Pico 2 has its onboard
LED on GPIO 25; a Pico 2 W uses a different LED connection.

The dependencies, boot/linker layout, and entry point follow
[Embassy's RP235x examples](https://github.com/embassy-rs/embassy/tree/main/examples/rp235x).
`build.rs` renders `memory.x.in` into the linker's `memory.x` and generates
`flash_layout.rs` for the storage driver from the same configuration. It also
enables the runtime and defmt linker scripts. Commit `firmware/Cargo.lock` to
pin the firmware dependencies.

The target and SWD runner are configured in `firmware/.cargo/config.toml`:

```toml
[build]
target = "thumbv8m.main-none-eabihf"

[target."thumbv8m.main-none-eabihf"]
runner = "probe-rs run --chip RP235x"
```

Run Cargo from the firmware directory so it loads this configuration. The shell
leaves the global Cargo target unset so host tools and tests can build for the host OS.

With an SWD probe, such as a Raspberry Pi Debug Probe:

```sh
probe-rs list
cd firmware
cargo build --release
DEFMT_LOG=debug cargo run --release
cargo size --release -- -A
```

`probe-rs run` flashes and displays RTT/defmt logs. `DEFMT_LOG` defaults to
`info`; the current firmware logs the initialization state and reason at startup.

Without a probe, hold BOOTSEL while connecting the board, then use the firmware's
ELF file (run from `firmware/`):

```sh
picotool info
picotool load -u -v -x -t elf target/thumbv8m.main-none-eabihf/release/firmware
```

For a GDB session, run this in one terminal inside the shell:

```sh
openocd -f interface/cmsis-dap.cfg -f target/rp2350.cfg -c 'adapter speed 5000'
```

Then, from the firmware directory in another shell:

```sh
gdb target/thumbv8m.main-none-eabihf/release/firmware \
  -ex 'target extended-remote localhost:3333'
```

The flake uses `openocd-rp2040` despite its name because it packages Raspberry
Pi's fork with [RP2350 support](https://github.com/raspberrypi/openocd/blob/sdk-2.2.0/tcl/target/rp2350.cfg).
For serial logs on Linux/WSL, use `tio /dev/ttyACM0`; on macOS, use
`tio /dev/cu.usbmodem1234` (adjust the device and baud rate as needed).
Close the terminal before opening the same port through Web Serial.

## Persistent storage

`firmware/src/storage.rs` provides an async key-value store backed by
[`sequential-storage`](https://docs.rs/sequential-storage/8.0.2/). Import it in
another firmware module with `use crate::storage::Storage`.

Create one instance using the flash peripheral and DMA channel 0, then keep it
in the task responsible for storage. For example, inside async initialization
after `embassy_rp::init`:

```rust
let mut storage = crate::storage::Storage::new(peripherals.FLASH, peripherals.DMA_CH0);
storage.initialize_metadata().await.unwrap();
if let Some(metadata) = storage.metadata().await.unwrap() {
    defmt::info!("Storage version: {}", metadata.version);
}
storage.store(1, b"hello").await.unwrap();

let mut bytes = [0u8; 32];
if let Some(length) = storage.read(1, &mut bytes).await.unwrap() {
    defmt::info!("Stored value: {=[u8]}", &bytes[..length]);
}
```

Key `0` is reserved for a single CRC-protected metadata record with two fields:
`magic` (`DOOHICKEY`) and `version`. `version` comes directly from the firmware
package version in `firmware/Cargo.toml` (`CARGO_PKG_VERSION`); there are no
separate schema or layout versions. Application `read` and `store` calls reject
key `0`; use `metadata()` to inspect it.

Call `initialize_metadata()` before application reads/writes. It creates the
record only when the entire partition is erased. A nonempty store without
metadata returns `MissingMetadata`; invalid magic/version encoding returns
`InvalidMetadata`. Neither case automatically formats the partition. As with
other reads, the storage library can repair interrupted writes while looking
up records; metadata is not a raw partition-header validation mechanism.

Existing metadata keeps its recorded version across firmware updates. Compare
`metadata.version` with `crate::storage::VERSION` and check compatibility or
migrate before using existing records. Afterward, explicitly call
`update_metadata_version().await` to record the running firmware's version.
It does not migrate application data itself or write again if versions match.
Do not automatically replace a different version at every boot, since that
would hide the version needed to decide which migration is required.

Application keys are `u32` values starting at `1`, excluding the reserved OTP
test keys `0xFFFFFF00..=0xFFFFFF02`; values are raw byte slices
up to 1024 bytes. Storing the same
key replaces its value. Reads return `None` for missing keys or `Some(length)`
for existing values, including empty ones. A too-small read buffer or oversized
value returns an error. Use a consistent serialization format for structured
data. Await operations to completion; do not cancel flash operations with a
timeout. Writes and erases can briefly block interrupts even with an async API.

For secrets, use [`EncryptedStorage`](firmware/src/storage/encrypted.rs). With
`master` explicitly loaded from OTP and `rng` seeded through `HardwareEntropy`:

```rust,ignore
use crate::storage::{EncryptedStorage, RecordKind};
use zeroize::Zeroizing;

storage.initialize_metadata().await?;
let mut secrets = EncryptedStorage::new(&mut storage, &master, &mut rng);
secrets.store(42, RecordKind::Credential, encoded_credential).await?;

let mut plaintext = Zeroizing::new([0u8; 983]);
if let Some(length) = secrets
    .read(42, RecordKind::Credential, &mut plaintext[..])
    .await?
{
    // Decode/use plaintext[..length]; the buffer is wiped when dropped.
}
```

This wrapper uses the existing XChaCha20-Poly1305 cipher and derives its key
once at construction. Each write gets a fresh nonce, and the authenticated
context binds the storage key, record kind, and stable wrapper encoding version
(`1`, independent of the firmware package version). The supported kinds are
`Credential`, `PairingKey`, and `Configuration`; their numeric tags must remain
stable. Use explicitly versioned serialization for each application's payload.

The plaintext limit is **983 bytes**, including any application serialization
headers. Empty values are supported. Reads return `None` only for missing keys;
invalid envelopes, wrong keys/kinds, and authentication failures return errors.
The entire caller output is cleared on entry, and plaintext is copied only
after the complete record authenticates. Temporary buffers are zeroized;
callers must also wipe their own plaintext when finished. The wrapper retains
only a derived cipher key and borrows the store/RNG. Metadata and OTP test keys
remain reserved. It performs no automatic key generation or plaintext migration.

Flash layout is configured in `firmware/build.rs`. The firmware region is always
3 MiB; storage starts at flash offset `0x00300000` and uses the remaining
capacity. The `flash-16mb` Cargo feature selects the larger chip; no feature
means 4 MiB. The generated Rust constants and linker regions always use the
same selection. `memory.x.in` is the shared template; generated files live in
Cargo's build output directory and should not be edited or committed.

| Build | Total flash | Storage offsets | Storage capacity |
| --- | --- | --- | --- |
| Default | 4 MiB | `0x00300000..0x00400000` | 1 MiB |
| `flash-16mb` | 16 MiB | `0x00300000..0x01000000` | 13 MiB |

This boundary was previously `0x003C0000`. Data written with that older layout
needs an explicit backup/migration or storage reset before using the new layout;
changing the partition start does not migrate existing records.

Build from `firmware/`, keeping the two artifacts in separate directories:

```sh
cargo build --release --target-dir target/4mb
cargo build --release --features flash-16mb --target-dir target/16mb
```

The ELF files are respectively:

```text
target/4mb/thumbv8m.main-none-eabihf/release/firmware
target/16mb/thumbv8m.main-none-eabihf/release/firmware
```

To build, flash, and see startup logs through an SWD probe, run the appropriate
command:

```sh
DEFMT_LOG=debug cargo run --release --target-dir target/4mb
DEFMT_LOG=debug cargo run --release --features flash-16mb --target-dir target/16mb
```

For BOOTSEL flashing, substitute the appropriate ELF path in the `picotool`
command above. Flash the 16 MiB variant only onto a board with 16 MiB of flash.
Changing the chip package feature (`rp235xa`/`rp235xb`) is independent of the
external flash capacity.

Construction does not erase or format the partition. The startup coordinator
inspects the partition and required records without generating secrets. Explicit
button-confirmed setup can create defaults and provision/seal the root when the
selected backend/build permits it. Metadata reads retain the storage library's
existing interrupted-write repair behavior. Application read/store calls also
reserve coordinator keys `0xFFFFFE00..=0xFFFFFE02`.

Records survive reset, but a full-chip erase during flashing removes them.
The raw store has wear leveling and CRC checks; use `EncryptedStorage` to
encrypt secrets. Neither layer provides transactions spanning multiple keys,
rollback protection, or secure deletion. Old values, including legacy plaintext,
may remain physically in flash after replacement.

## USB composite device

[`firmware/src/usb`](firmware/src/usb/README.md) uses Embassy USB to expose FIDO
HID plus CDC ACM serial through the board's native USB port. Development VID/PID
are `c0de:d001`. HID supports CTAPHID INIT/PING, fragmentation, arbitration,
timeouts, cancellation, and keepalives. Bounded canonical CBOR decoding and a
public `authenticatorGetInfo` response are connected. The development FIDO_2_0
profile supports ES256 registration, packed self-attestation, discoverable
accounts and allow-list assertions with fresh GPIO 23 confirmation (GPIO 25 flashes).
Protocol-2 ClientPIN, PIN-based UV and [discoverable credentials](docs/discoverable-credentials.md)
are implemented; credential management and extensions remain unavailable. See [PIN setup and tests](docs/client-pin.md). See the
[credential milestone guide](docs/credential-milestone.md) for encrypted storage
and the register/update/authenticate test.


CDC accepts length-prefixed binary frames (`u16` big-endian length followed by
payload), with a public `INFO` request returning device information. The current
handler rejects other commands; authenticated backups are not enabled. RTT logs
remain on the debug probe. See the USB guide for connection handling and the
on-device smoke test:

```sh
cd firmware
python tools/usb_smoke.py --serial /dev/ttyACM0
```

The tool needs `hidapi` and `pyserial` in a Python environment; the guide shows
setup and the corresponding macOS/Windows serial port names.

## CTAP protocol modules

[`firmware/src/ctap`](firmware/src/ctap/README.md) contains the initial CTAP 2.3
module layer for an ES256 authenticator with discoverable credentials and
ClientPIN protocol 2. It provides typed command/backend interfaces, status codes,
credential-management inputs, and mandatory extension helpers for `credProtect`
and `hmac-secret`. The existing `crypto::ctap` module supplies cryptographic
primitives. The heap-free decoder validates canonical CBOR and COSE agreement
keys and constructs borrowed requests using fixed-size scratch space. Read-only
getInfo, makeCredential and allow-list getAssertion use the encrypted repository.
This is a limited operational profile, not a conformant CTAP 2.3 authenticator. Target `FIDO_2_3`
profile constants are not advertised as completed capabilities.

## OTP keys

[`firmware/src/otp.rs`](firmware/src/otp.rs) manages the device master key and
secure-boot public-key hash using typed, write-once access. Hardware OTP is the
default; irreversible programming requires `otp-provisioning`. Master-key reads
require the dedicated page to be sealed against writes, Non-secure reads, and
bootloader access. Secure-boot activation and device-wide lockdown remain a
separate provisioning step; the private boot signing key stays off-device.

For development, `insecure-test-otp` uses the storage module instead of hardware
OTP. This intentionally stores test keys in plaintext flash and emits a build
warning. It cannot be combined with `otp-provisioning`.

See the [OTP guide](firmware/src/otp/README.md) for the fixed row layout, API,
flash-backed test commands, and guarded-read/provisioning requirements. The
[initialization guide](firmware/src/init/README.md) documents physical confirmation,
durable setup and resume. Boot/startup inspection never automatically burns OTP.

## Cryptography

The reusable `no_std` crypto library lives in `firmware/src/crypto/` and is
available to firmware modules as `crate::crypto`. It provides ES256 signing,
CTAP PIN/UV protocols 1/2, authenticated encryption for stored secrets, and a
PSK-authenticated Noise record layer for serial transfers. Its RP2350 entropy
adapter uses Embassy's hardware TRNG with health checks enabled and no insecure
fallback seed. Explicit initialization uses it to generate root/credential keys
and fresh encryption nonces; startup loading preserves existing keys.

See the [crypto module guide](firmware/src/crypto/README.md) for library research,
usage, wire formats, tests, and the remaining pairing, provisioning, and authorization
requirements. Raw `Storage::store` calls still store exactly the bytes supplied;
use the encryption API explicitly for secrets.

## Nuxt with npm

Create the web app once, selecting npm if prompted:

```sh
npm create nuxt@latest web
cd web
npm install
npm run dev
```

Commit `web/package-lock.json`; teammates can then run `npm ci` in `web/`.
Nuxt and its dependencies stay managed by npm. Node.js 26 is the active LTS
release as of November 2026, according to the [Node.js release schedule](https://github.com/nodejs/Release#release-schedule),
and meets [Nuxt's Node requirements](https://nuxt.com/docs/4.x/getting-started/installation).

Use a host-installed Chromium/Chrome browser for WebUSB and Web Serial. The shell
does not need to supply a browser. Serve the app on `http://localhost:3000` during
development, or HTTPS elsewhere: these APIs require a secure context. A plain
HTTP LAN IP does not qualify. Access `navigator.usb` and `navigator.serial` only
on the client (for example, inside a click handler in a `.client.vue` component),
and request devices/ports from a user gesture. Feature-detect both APIs.

For a composite FIDO2 device, use a vendor-specific interface for WebUSB and a
CDC ACM interface for Web Serial. WebUSB blocks HID interfaces, and Chromium's
WebHID implementation blocks the FIDO usage page. Browser authentication uses
WebAuthn; the extra interfaces can carry your management/debug protocol. See the [WebUSB specification](https://wicg.github.io/webusb/)
and [Chromium's HID blocklist](https://github.com/chromium/chromium/blob/main/services/device/public/cpp/hid/hid_blocklist.cc).

Chrome's `chrome://device-log` and `chrome://usb-internals` help diagnose USB
discovery and access problems. See the official [WebUSB guide](https://developer.chrome.com/docs/capabilities/usb)
and [Web Serial guide](https://developer.chrome.com/docs/capabilities/serial).

## Linux device permissions (once per machine)

`nix develop` supplies programs, but cannot configure the host's udev service or
grant access to USB and serial devices. Configure this on each development host.

On **NixOS**, add the following to your system configuration, replacing
`your-user` with your login name, then rebuild and log in again:

```nix
{ pkgs, ... }: {
  services.udev.packages = with pkgs; [ picotool probe-rs-tools openocd-rp2040 ];
  users.groups.plugdev = {};
  users.users.your-user.extraGroups = [ "plugdev" "dialout" ];
}
```

Use a recent nixpkgs in your system configuration that provides these packages.
The upstream [picotool rules](https://github.com/raspberrypi/picotool/blob/master/udev/60-picotool.rules)
cover BOOTSEL devices, and the [probe-rs rules](https://probe.rs/docs/getting-started/probe-setup/)
cover supported probes. Your running firmware's USB identity needs its own rule.

On **other Linux distributions**, install the upstream picotool and probe-rs
rules in `/etc/udev/rules.d/` and follow their group setup instructions. Add your
user to the distribution's serial access group (often `dialout`, sometimes
`uucp`). If a rule uses `plugdev`, ensure that group exists and your user belongs
to it. Log in again after changing groups. Reload rules with:

```sh
sudo udevadm control --reload-rules
sudo udevadm trigger
```

For your **running firmware**, use its actual VID/PID in narrowly scoped rules.
For example, replace `vvvv` and `pppp` below with the four-digit hexadecimal IDs
shown by `lsusb`:

```udev
# /etc/udev/rules.d/70-rp2350-fido-dev.rules
SUBSYSTEM=="usb", ATTR{idVendor}=="vvvv", ATTR{idProduct}=="pppp", MODE="0660", TAG+="uaccess"
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="vvvv", ATTRS{idProduct}=="pppp", MODE="0660", TAG+="uaccess"
SUBSYSTEM=="tty", ATTRS{idVendor}=="vvvv", ATTRS{idProduct}=="pppp", MODE="0660", TAG+="uaccess"
```

On NixOS, place these rule lines in `services.udev.extraRules` instead. `uaccess`
grants access to the active local desktop session on hosts using systemd-logind;
for remote/headless sessions, use a dedicated device group and membership instead.
Reconnect the device after installing rules. BOOTSEL and running firmware can
have different USB IDs; granting access to one does not grant access to the other.

Sandboxed browsers may need additional host permissions for USB/serial access.
If a serial port is intermittently busy, check whether ModemManager or a serial
terminal has opened it.
