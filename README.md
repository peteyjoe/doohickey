# Experimental branch: Windows passkey sign-in fix

**Status: experimental. Windows sign-in works on this branch. This is a
workaround, not a finished fix.** iOS is out of scope (see below).

## The problem

On Windows, signing in with a passkey stopped at the "Sign in with a passkey"
dialog after the user entered the correct PIN. Registration worked, and a
credential saved on Windows could be used to sign in on Linux and macOS. The
failure was only in sign-in on Windows.

The Windows WebAuthN event log (Event Viewer, Applications and Services Logs,
Microsoft, Windows, WebAuthN, Operational) showed password-style errors such as
"incorrect password". That is consistent with the device returning
`PinAuthInvalid` (0x33), but we did not capture the CTAP traffic to confirm it.

## The change

One line was removed. In the GetAssertion arm of `execute` in
`src/ctap/authenticator.rs`, the call to `session.consume()` after the assertion
is gone:

```rust
let result = assertion(repository, request, presence, output, verified, session, now).await;
let expired = verified && !session.grant_valid(presence.now_ms());
// session.consume();   <- removed on this branch (GetAssertion only)
if expired { Err(Status::PinAuthInvalid) } else { result }
```

The MakeCredential arm still calls `session.consume()`. Nothing else was changed.

## Why this probably works (unconfirmed)

`session.consume()` sets the PIN token to `None`, so every token is single-use
("a fresh token for another operation", per the comment in `pin_session.rs`).
Our best explanation is that Windows makes more than one getAssertion request
on the same PIN token. The first request succeeds and the token is discarded,
so the second fails in `Session::authorize()` with `PinAuthInvalid`. Chrome on
Linux and macOS appears to need only one request per sign-in, so it never hit
this.

We have not confirmed the Windows command sequence. The explanation fits the
symptoms and the one-line change fixed them, but it is a hypothesis.

## Security trade-off

With `consume()` removed, a token that was used for getAssertion can be reused
until it expires. What still limits that:

- The token lifetime is 30 seconds (`LIFETIME` in `pin_session.rs`).
- After its first use the token is bound to one relying party.
- Each request must carry its own valid HMAC over its own client data hash,
  which only the platform holding the token can compute.
- Each assertion still needs a fresh physical button press.

This is acceptable for an experiment, but it has not been reviewed against the
spec, so do not treat it as the intended design.

## What has been tested

| Check | Result |
| --- | --- |
| Windows sign-in on webauthn.io with an existing credential | Works |
| Windows sign-in on GitHub with an existing credential | Works |
| Registering a new passkey on Windows after the change | Not tested |
| Repeated sign-ins, or waiting more than 30 seconds between attempts | Not tested |
| Linux and macOS sign-in after the change (regression check) | Not tested |
| Non-discoverable (allow-list) credentials | Not tested |

## Steps toward a proper fix

1. **Confirm the root cause.** Log only command IDs and result codes for a
   Windows sign-in and a Linux sign-in, and compare them. Never log PINs,
   requests or account data (see `src/ctap/README.md`). A RAM ring buffer dumped
   by a serial command after the response is sent avoids flash writes in the
   middle of a CTAP exchange.
2. **Read the spec rules for PIN/UV auth tokens**, in the CTAP 2.3 document
   linked from `src/ctap/README.md`: what a token may do after use, how
   permissions and RP binding apply, and when it must be invalidated.
3. **Implement those rules instead of never consuming.** For example, keep the
   token for getAssertion until it expires or is invalidated, and keep the
   existing consume-on-use behaviour only where the spec requires it.
4. **Add a host test** that makes two getAssertion calls on one token, plus one
   where the token has expired.
5. **Re-test** on Windows, Linux and macOS, on at least two sites, with
   discoverable and non-discoverable credentials, and also register a new
   passkey.

## Separate experiment: the getInfo version string

`getInfo` (`src/ctap/info.rs`) reports `FIDO_2_0`, but also advertises
`pinUvAuthToken` and `credMgmt`, which belong to CTAP 2.1. Platforms may behave
differently depending on the version list. Changing it could alter which PIN
flow Windows uses, so test it on its own and not together with the token fix.

## iOS (known not working, not investigated)

On iOS the key is found, but the PIN is always rejected. The cause is unknown
and this branch does not address it. One untested hypothesis is a PIN protocol
mismatch: the device only supports protocol 2.

## Building and flashing

Use the correct flash-size feature for the board. This board, the NOLOGO RP2350 USB, is **16 MiB**.

```sh
cd firmware
cargo build --locked --release --features flash-16mb --target-dir target/16mb
python3 tools/check_update.py target/16mb/thumbv8m.main-none-eabihf/release/firmware --flash-mb 16
```

- An earlier build with a plain `cargo build --release` (the 4 MiB default) left
  the board reporting `recovery_required`. Rebuilding with `--features flash-16mb`
  put it back in a good state. The most likely cause is a flash geometry
  mismatch, which `docs/reset-and-upgrades.md` says stays blocked, but we did not
  capture the exact reason text.
- Never enable `otp-provisioning` (irreversible hardware writes) or
  `insecure-test-otp` for this work. `check_update.py` rejects such images.
- Do not erase flash or storage when updating. See `docs/reset-and-upgrades.md`
  for the supported flashing commands (picotool or probe-rs).
- **Do not use the BOOTSEL hold gesture while the device reports
  `recovery_required`.** Per `docs/reset-and-upgrades.md` it requests a
  destructive factory reset that erases credentials and the PIN.
- For Windows testing, the board must be attached to Windows, not to WSL through
  usbipd.