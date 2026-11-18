# Alpha 0.3: serial backups and browser workflows

This is an experimental authenticator build, without secure boot. The browser
application is `website-final`; its existing layout/colors remain in use.
This build deliberately exposes credential backup over CDC and does not claim
CTAP/FIDO conformance or certification. The existing HID registration, ClientPIN,
management and extensions stay separate from serial authorization.

## Use

1. Run `npm ci && npm run dev` in `website-final`, or build with `npm run build`.
   Use localhost or HTTPS in desktop Chrome/Edge. Serial, WebUSB and WebAuthn
   require browser permissions. Close other serial monitors before connecting.
2. In Flash, choose the physical flash size. For ordinary updates leave the
   first-installation checkbox off. Boot with BOOTSEL, connect, and flash.
   Images are checked against the served SHA-256 manifest and strict UF2 address,
   family, ordering and duplicate checks before erasing. Writes stay below 3 MiB
   and are read back before completion. Reconnect normally afterward.
3. **Blank OTP only:** explicitly select the first-installation image. It permits
   programming/sealing the OTP master root after a local release/three-second
   hold/release. This permanently consumes OTP master-key storage. It does not
   program secure-boot trust keys or enable secure boot. Use an ordinary image
   afterward for updates. Existing initialized devices do not reprovision OTP.
4. Connect in Backup and refresh status. A valid upgrade from 0.1.0/0.2.0 preserves
   credentials/PIN/settings; interrupted operations resume before service starts.
   New setup requires the local three-second confirmation. Recovery uses the
   existing destructive reset gesture, never serial commands that bypass consent.
5. Pair over a **trusted local USB connection and trusted website**. Press/release
   BOOTSEL when prompted. Save the client key with the Save pairing key button.
   One client is supported; pairing again revokes the old key. Nothing is stored
   in localStorage. The client key is a bearer secret, not the authenticator PIN.
6. Paste that key, enter/confirm a backup password of at least 12 characters and
   export. A fresh button action approves export. The saved file is encrypted.
7. Restore replaces the target's entire credential database, PIN and pairing.
   Provide the saved password and the **target device's** pairing key. Approve
   the transfer, then approve the commit after upload/validation. Re-pair and set
   a new FIDO PIN using native FIDO management afterward. OTP remains the target's.
8. The Test section registers a real resident test credential and verifies a
   fresh assertion's signature, origin, challenge, RP hash and UP. UV is preferred
   and its actual result is shown; a device without a PIN can be tested. This is
   a local diagnostic, not a production relying-party login or attestation verifier.

The restore website temporarily decrypts the file to reject a wrong password
before upload; the firmware independently authenticates it again. Use a trusted
origin. Browser JavaScript cannot promise reliable erasure of every GC-managed
copy. Passwords/client keys are not sent to a website server by these workflows.

## Protocol

CDC uses existing u16 big-endian length framing, max 1040 bytes. There is no COBS
or legacy placeholder opcode protocol. INFO is public JSON. All other operations
run through a mailbox to the same single storage owner as HID. Disconnect/DTR/
configuration changes invalidate the connection and in-progress authorization.
Flash futures are awaited through completion, even if a transport goes away.

PAIR + 32 random host bytes requires fresh physical confirmation and stores the
pair secret with encrypted RecordKind::PairingKey at `0x05000000`. This bootstrap
assumes the initial USB path is trusted: it does **not** resist an active attacker
on that path. It is not a PAKE or Noise handshake. Future use authenticates a
fresh hardware-seeded 32-byte challenge (30-second lifetime) with HMAC-SHA256.
The session master is HMAC(pair, `session` || challenge). Encrypted device key
confirmation prevents accepting an unauthenticated responder.

Transport uses the existing HKDF/XChaCha20-Poly1305 SecretBox envelope with
separate `serial client v1` and `serial device v1` AAD, random 192-bit nonces and
strict LE32 request sequence numbers. Replay/order/tag failures close the
session. Sessions expire after five minutes or 4096 requests; no session survives
reboot. This PSK construction has **no forward secrecy**. The browser uses noble
ciphers and native WebCrypto for HKDF/HMAC/PBKDF2; no custom cipher implementation.

Encrypted commands: 1 grants export(1)/restore(2), requiring physical presence;
2 starts export with an external 32-byte backup master; 3 reads bounded chunks;
4 begins restore with size/master; 5 appends ordered chunks; 6 verifies and commits
restore with a second physical confirmation. Grants last two minutes and are
consumed into one transfer, not reusable general credential permissions. There
are no serial PIN, OTP-write, arbitrary-storage or reset commands. Device/command
errors invalidate the session; reconnect/re-authenticate after errors/timeouts.

Backup file: `DOOHEXP1` || salt16 || SecretBox envelope. PBKDF2-HMAC-SHA256,
600,000 iterations yields the external master, then the existing SecretBox HKDF
provides the encryption key. Secrets are re-encrypted under that password-derived
master, independent of either device's OTP root. Do not lose the password.

Authenticated plaintext: `DOOHBAK1` || credentialKey32 || repeated
(key LE32, length LE16, raw encrypted record). Only credential namespace 01 and
resident-directory namespace 030000xx are allowed. PIN, pairing, lifecycle and
OTP are excluded. Size is bounded to **32 KiB plaintext**, at most 256 distinct
keys; exports fail rather than truncate. History/tombstones consume this budget.
This is an alpha memory bound, not the device's total credential storage size.

Restore validates the full file, duplicate/allowed keys, each record's AEAD,
known credential encodings, private scalar validity and directory member presence
before committing. Root-encrypted staging chunks occupy `0xFFFFFD00..FD25`.
The reserved coordinator range is `0xFFFFFD00..0xFFFFFE04`. A mode-3 lifecycle
transaction commits the imported credential key and restore intent, then cleanup
and installation replay forward after interruption. State is never exposed as
ready midway; target root/boot trust are never imported. Staging chunks remain
reserved/encrypted and are reused by later restores.

Backups preserve credential IDs, private keys, extension seeds and counters as
of export. A restored clone can roll counters back or duplicate an authenticator;
RPs may reject it. Prefer replacement recovery rather than running multiple
active clones. No protected monotonic anti-rollback or physical secure erasure
is provided. Unsigned firmware and a compromised browser/device remain outside
this alpha's protection boundary.

## Build artifacts and evidence

From firmware, run `python3 tools/package_alpha.py`. It builds ordinary and
opt-in provisioning images for both capacities, checks the ELF write ranges,
converts UF2 with picotool and generates `website-final/public/firmware/manifest.json`.
No device is accessed. The manifest detects accidental artifact corruption;
it is not a signature against a malicious site. PICOBOOT follows Raspberry Pi's
[protocol headers](https://github.com/raspberrypi/pico-sdk/blob/master/src/common/boot_picoboot_headers/include/boot/picoboot.h).

Quick checks cover initialization/restore transaction interruption, firmware
Clippy/builds, Rust-to-browser SecretBox interoperability and tag tampering, UF2
parsing and Nuxt production build. Physical WebUSB, USB serial/presence and full
cross-device credential restore remain release qualification work; compilation
alone is not evidence of a working hardware alpha. No board was flashed, reset,
paired or OTP-programmed during this implementation.

## BOOTSEL presence input

All runtime confirmation uses the standard flash-CS BOOTSEL button, sampled
on core 0 through a RAM-resident reader with interrupt, core-1 and flash-DMA
exclusion. No external GPIO 23 button is required. Press BOOTSEL **after**
normal boot for application confirmation; holding it during power-up/reset
still enters the ROM installer. Setup/reset require release, three-second hold
and release; other confirmations require a fresh press/release. Boards must
wire BOOTSEL to flash CS in the standard way. The status LED remains GPIO 25;
boards with another LED pin may need a separate LED configuration.
