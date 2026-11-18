# ClientPIN and PIN-based UV

The development authenticator supports PIN/UV protocol 2: getRetries,
getKeyAgreement, setPIN, changePIN, legacy getPinToken and scoped
getPinUvAuthTokenUsingPinWithPermissions. Protocol 1 and built-in biometric UV
are unsupported. GetInfo includes `[2]`, `pinUvAuthToken=true` and a dynamic
`clientPin` boolean: false means supported/unset, true means configured. It still
reports the development FIDO_2_0 profile, not CTAP 2.3 conformance.

## Persistence and failure policy

Both PIN records use `EncryptedStorage`, Configuration kind, and the existing
replaceable credential key. Changing a PIN never changes credential signing or
encryption keys. These addresses must not be reused by other application code:

| Storage key | Plaintext format |
| --- | --- |
| `0x02000000` | 26 bytes: `DOOHPIN1`, LEFT(SHA256(PIN),16), retries u8, code-point length u8 |
| `0x02000001` | 8 bytes: `DOOHPIN1` initialization witness |

Plaintext PINs are never stored. The encrypted truncated hash is the CTAP
CurrentStoredPIN verifier, protected by the same key hierarchy as credentials.
PINs must be valid UTF-8, have at least four Unicode code points, contain no NUL,
and occupy at most 63 bytes. Platforms normalize to NFC before transmission.

First set writes/verifies the witness before writing/verifying the PIN state.
Both absent means a pre-PIN device. Only one absent, corrupt ciphertext or an
unknown format fails closed; it never silently reverts to unset. A power cut
during first setup can therefore leave recovery required for PIN operations.
There is no automatic destructive repair. [Physically confirmed reset/recovery](reset-and-upgrades.md) handles
this explicitly; do not erase the records to clear a user's forgotten PIN.

At most eight PIN attempts are allowed. Each candidate consumes a persisted,
read-back attempt before decryption/comparison. Correct PINs restore eight;
zero persists across reboot and blocks PIN use until a future explicit CTAP
reset. Three consecutive incorrect PINs impose a temporary block until reboot.
USB disconnect, channel changes and resynchronization do not reset that block.
Failed PIN checks invalidate key agreement; the next exchange creates a fresh
key with the hardware-seeded RNG. Writes are awaited through completion.

## Authorization

Tokens are random 32-byte RAM-only secrets. Scoped tokens support makeCredential/getAssertion and credential management.
MC/GA require an RP ID; global CM enumeration uses an unbound CM grant, while
CM deletion and label updates may be RP-bound. Other permissions are rejected.
Legacy grants include the implemented default permissions and bind to the
first RP used for a credential operation. All credential authorization uses protocol-2 HMAC over clientDataHash.

Tokens expire after 30 seconds and MC/GA grants are consumed after a credential operation;
obtain a fresh token for another credential operation. CM grants remain live
for the management session within that deadline. Expiry is rechecked before releasing
the response, including after waiting for the button. Cancel, disconnect,
resynchronization, channel switching and PIN changes invalidate tokens.
No tokens or key-agreement private keys survive reboot.

Verified PIN tokens set UV in authenticatorData. They do not stand in for UP:
normal credential operations still need a fresh BOOTSEL press/release, with
GPIO 25 flashing. `uv=true` without a PIN token remains an unsupported request
for built-in verification. Setting a PIN makes new credentials require token
authorization. Existing allow-list credentials can still produce UP-only or
silent assertions when no token is supplied, as permitted by this profile;
callers that need UV must request and verify it.

No storage layer prevents rollback of a valid flash snapshot. Deleting both PIN
records, downgrading to firmware that ignores PINs, or bypassing trusted firmware
is outside this protection. Signed update/downgrade policy, secure boot, real OTP
qualification remains an alpha requirement. Reset is implemented with physical confirmation. This is not a serial backup
password or serial authorization mechanism.

## Try it

Use a Python environment with `fido2>=2,<3` and the board's native USB interface.
See [the credential guide](credential-milestone.md) for a pinned Nix environment.
From `firmware/`:

```sh
python tools/pin_manage.py status
python tools/pin_manage.py set       # Writes your chosen PIN; prompts privately
python tools/pin_manage.py change    # Requires current PIN
python tools/credential_smoke.py register --pin --state /tmp/pin-test.json
python tools/credential_smoke.py authenticate --pin --state /tmp/pin-test.json
```

Do not put PINs in command-line arguments. Preserve your original public
credential fixture and authenticate it with `--pin` after an update to verify
existing credentials remain usable with UV. No default PIN is installed and
development tests do not set the physical device's PIN automatically.

## Validation

Host tests cover policy, changes, preserved credential keys, durable retries,
temporary/permanent blocking, wrong RP/permissions, expiry, replay and missing
records. Actual sequential-storage/NOR tests interrupt each byte of a retry
write and reopen the map; state stays configured and the old/new retry count
remains bounded. They do not qualify physical power loss or garbage collection.

An independent Yubico client exercises the actual codec, crypto, repository and
handlers in a host-only simulator. The simulator has deterministic secrets and
synthetic UP, never accesses physical hardware, and must never be used as firmware:

```sh
cargo build --locked -p doohickey-crypto --example ctap_simulator --target x86_64-unknown-linux-gnu
python tools/pin_interop.py target/x86_64-unknown-linux-gnu/debug/examples/ctap_simulator
```

The interop test checks set/change, protocol 2, scoped UV registration/assertion
signatures, retries across simulated reboot, and legacy token retrieval.
Physical PIN setting/change, lockout, UV and persistence still need user-driven
qualification with the chosen PIN; read-only hardware checks do not establish it.

Basis: [CTAP 2.3 section 6.5](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN),
[Yubico python-fido2](https://developers.yubico.com/python-fido2/).
