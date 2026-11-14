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
you add to the firmware crate, rather than a Nix package.

Once you create a firmware crate (for example, in `firmware/`), put the target
and runner in **that crate's** `.cargo/config.toml`:

```toml
[build]
target = "thumbv8m.main-none-eabihf"

[target.thumbv8m.main-none-eabihf]
runner = "probe-rs run --chip RP235x"
```

Use Embassy's RP235x examples for the Cargo features, linker scripts, memory
layout, boot metadata, and USB setup appropriate to your board. Run Cargo from
the firmware directory so it loads this configuration. The shell leaves the
global Cargo target unset so host tools and tests can build for the host OS.

With an SWD probe, such as a Raspberry Pi Debug Probe:

```sh
probe-rs list
cd firmware
cargo build --release
cargo run --release
cargo size --release -- -A
```

`probe-rs run` flashes and displays RTT/defmt logs when the firmware implements
them. `DEFMT_LOG` defaults to `info`; override it as needed.

Without a probe, hold BOOTSEL while connecting the board, then use the firmware's
ELF file (replace `firmware-name` with your binary's name):

```sh
picotool info
picotool load -u -v -x -t elf target/thumbv8m.main-none-eabihf/release/firmware-name
```

For a GDB session, run this in one terminal inside the shell:

```sh
openocd -f interface/cmsis-dap.cfg -f target/rp2350.cfg -c 'adapter speed 5000'
```

Then, from the firmware directory in another shell:

```sh
gdb target/thumbv8m.main-none-eabihf/release/firmware-name \
  -ex 'target extended-remote localhost:3333'
```

The flake uses `openocd-rp2040` despite its name because it packages Raspberry
Pi's fork with [RP2350 support](https://github.com/raspberrypi/openocd/blob/sdk-2.2.0/tcl/target/rp2350.cfg).
For serial logs on Linux/WSL, use `tio /dev/ttyACM0`; on macOS, use
`tio /dev/cu.usbmodem1234` (adjust the device and baud rate as needed).
Close the terminal before opening the same port through Web Serial.

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
