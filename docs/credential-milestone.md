# Credential registration and update test

The firmware implements a development FIDO_2_0 profile: ES256 non-discoverable
credentials, packed self-attestation, allow-list assertions and physical user
presence. This supports a registration/login flow with user verification
discouraged and resident keys discouraged. It is not the final CTAP 2.3 profile
or a certified authenticator. PIN-authorized credential management and credential extensions are implemented;
[Reset and recovery](reset-and-upgrades.md) are implemented. See [the current scope](credential-management-and-extensions.md).
[Discoverable credentials](discoverable-credentials.md) are implemented; the guide
below still describes the saved allow-list fixture flow. [ClientPIN and PIN-based UV](client-pin.md) are now
implemented; use `--pin` with the credential tool once a PIN is set.

`application.rs` owns initialization, flash, the TRNG-seeded CSPRNG, and GPIOs.
The HID backend copies requests to `ctap::exchange::Exchange`. USB keeps servicing
keepalives, cancel and disconnect while the owner awaits presence or storage.
Cancellation never drops a flash future. Disconnect/resynchronization suppress
obsolete replies. GPIO 25 flashes while confirmation is needed; release BOOTSEL,
press it, then release it. Every edge is debounced for 30 ms. A held button and
the earlier setup confirmation cannot authorize a new request. Timeout comes
from the initialized settings (30 seconds by default).

Serial INFO reports `ctap_ready=true` only after initialization validates and
hardware entropy seeds the application RNG. This means the limited profile is
available, not full CTAP 2.3 compliance. Serial authentication readiness stays
false; CDC cannot read or change credentials.

## Persistent repository

`storage::credentials::Repository` provides create, read, counter advance,
user-handle replacement and logical deletion. Mutations are single-value writes
through `EncryptedStorage`, followed by authenticated readback. The encryption
key is the replaceable credential key from initialized state, not the OTP root.
No key material or account values have Debug/Clone implementations.

The allocated namespace is `0x01000000..=0x01ffffff`. Other application modules
must not use it. A non-discoverable record uses a 202-byte plaintext / 243-byte envelope plus
the underlying map overhead. Capacity follows the selected storage partition;
there is no fixed credential-count limit that differs between firmware variants.
Random address collisions are checked without overwriting records.

The stable 60-byte credential ID contains `DOOHCID1`, the LE32 storage key,
16 random bytes and a 32-byte HMAC over that prefix and rpIdHash. The HMAC key
uses the fixed `DOOHICKEY credential id v1` derivation domain. Invalid/foreign
IDs and IDs for another RP return no match without storage access. Missing or
corrupt records behind a valid owned ID produce an integrity error.

The persistent plaintext layout is fixed, independent of firmware version and
flash geometry. Future incompatible changes require explicit format support or
migration; do not change these bytes in place:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | `DOOHCR01` format marker |
| 8 | 1 | Active=1, tombstone=0 |
| 9 | 60 | Credential ID |
| 69 | 32 | rpIdHash |
| 101 | 1 | User-handle length, 1..64 when active |
| 102 | 64 | User handle, zero padded |
| 166 | 32 | P-256 private scalar |
| 198 | 4 | LE32 per-credential signature counter |

Assertions persist the next counter before exposing a signature. A failed
acknowledgement may skip a count; overflow is an error. Deletion clears the
user/key fields and persists an authenticated tombstone; addresses are never
reused. An interrupted creation can leave an unpublished credential consuming
space. Discoverable records additionally use the directory commit described in the
[discoverable credential guide](discoverable-credentials.md); management
enumeration commands remain unimplemented.
Old encrypted flash values remain: logical deletion is not secure erasure,
and neither the repository nor the map prevents rollback of a valid snapshot.

## Exercise the milestone

Install the independent Yubico client in a host Python environment:

```sh
python3 -m venv /tmp/doohickey-fido-test
/tmp/doohickey-fido-test/bin/pip install 'fido2>=2,<3'
cd firmware
/tmp/doohickey-fido-test/bin/python tools/credential_smoke.py register \
  --state /tmp/doohickey-test-credential.json
```

Connect the board's native USB port, not only the debug probe. Press/release
BOOTSEL when prompted. The tool verifies packed self-attestation independently
and saves only the credential ID/public key/AAGUID/counter. Registration creates
one persistent test credential for `doohickey.test`. Keep the fixture: this
non-discoverable credential cannot be looked up without its ID.

On NixOS, an isolated environment using this repository's pinned nixpkgs is:

```sh
# Run from the repository root; no pip or global installation required.
nix shell --impure --expr 'let f = builtins.getFlake (toString ./.); p = import f.inputs.nixpkgs { system = builtins.currentSystem; }; in p.python3.withPackages (ps: [ ps.fido2 ])' \
  --command python firmware/tools/credential_smoke.py register --state /tmp/doohickey-test-credential.json
```

Use the same prefix with `authenticate` for subsequent commands.

```sh
/tmp/doohickey-fido-test/bin/python tools/credential_smoke.py authenticate \
  --state /tmp/doohickey-test-credential.json
```

Press/release again. Then build/download a compatible new image using the same
flash size and OTP policy. Inspect the image addresses and use sector programming,
not chip erase; the storage boundary stays at `0x10300000`. For the connected
4 MiB flash-emulated-OTP test board:

```sh
cargo build --locked --release --features insecure-test-otp --target-dir target/otp-test-4mb
probe-rs download --chip RP235x --restore-unwritten --verify --reset \
  target/otp-test-4mb/thumbv8m.main-none-eabihf/release/firmware
/tmp/doohickey-fido-test/bin/python tools/credential_smoke.py authenticate \
  --state /tmp/doohickey-test-credential.json
```

The final assertion must verify with the original saved public key and have a
higher counter. This is the physical milestone; do not substitute a newly
registered credential. `--silent` tests signature/counter persistence without
UP, but is preflight only and does not establish a WebAuthn login.

Host checks import the actual repository, codec, handlers and crypto. They
cover RP binding, signatures, reconstruction, deletion, corruption, errors,
counter exhaustion, cancellation and button debounce. The real sequential-storage
map is also exercised over simulated NOR flash with every-byte interruption of
counter/tombstone writes. This does not qualify physical flash erase/power-loss
behavior, garbage collection, real OTP or secure boot.

```sh
cargo test --locked -p doohickey-crypto --target x86_64-unknown-linux-gnu
```

Basis: [CTAP makeCredential/getAssertion algorithms](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential),
[Yubico python-fido2](https://developers.yubico.com/python-fido2/).
