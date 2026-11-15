# CTAP module foundation

`crate::ctap` is the protocol layer; `crate::crypto::ctap` remains the portable
cryptographic implementation. The selected target is ES256, discoverable and
non-discoverable credentials, ClientPIN with protocol 2, credential management,
`credProtect`, and `hmac-secret`. No biometric, large-blob, enterprise-attestation,
authenticator-config, or vendor backup modules are added in this step.

This is **not yet a working CTAP authenticator**. The typed command boundary,
dispatch, algorithm selection, permission parsing, credential-protection filter,
and protocol-2 hmac-secret helper are implemented. CBOR/COSE decoding/encoding,
the stateful command algorithms, durable credential/PIN storage, user-presence
integration, and command deadlines are not connected. FIDO USB HID framing now
lives in [usb](../usb/README.md), with a default backend that rejects unfinished
commands. TARGET_* constants describe
the intended profile; they are not a completed getInfo response or a compliance
claim. The main application runs startup inspection before USB transport, then
supports local button-confirmed base initialization. This provisions a root only
under the selected OTP build policy and prepares settings/credential key; it
does not implement CTAP credential operations. The [alpha roadmap](../../../docs/alpha-roadmap.md) tracks
the application algorithms and qualification still required.

## Modules

| File | Responsibility |
| --- | --- |
| `mod.rs` | Module entry and target profile constants |
| `commands.rs` | Core command IDs, typed requests, mandatory backend interface, dispatch |
| `status.rs` | Nonzero CTAP error codes and result type |
| `credentials.rs` | Credential command inputs and ES256 algorithm selection |
| `pin_uv.rs` | ClientPIN inputs and requested permission masks |
| `credential_management.rs` | Enumeration, deletion, and user-update inputs |
| `extensions.rs` | `credProtect` filtering and encrypted `hmac-secret` processing |

Core dispatch covers makeCredential, getAssertion, getInfo, ClientPIN, reset,
getNextAssertion, credentialManagement, and selection. Selection shares the core
interface without adding a separate feature module. Profile-optional commands
and old prototype codes are rejected by Command::try_from.

## Backend contract

Implement `ctap::Handlers` on the eventual single owner of storage, RNG, PIN/UV
state, user presence, clock, and pending operations. Every method is required;
there are no default success responses or production dummy handlers. Typed input
is not proof of validity, user verification, or permission. Each handler must
follow its normative algorithm, including its specified error precedence.

`ctap::execute` accepts a typed `Request` and transport-assigned `RequestContext`,
then routes it to a handler. The context's session ID is not taken from CBOR and
is not an authorization token. Handlers encode the response CBOR body into the
provided output and return its length. Reset and selection return an empty body.
The transport adds the leading CTAP status byte. A backend error, or an invalid
reported length, clears the whole response buffer. Errors cannot encode success.

The future codec must validate canonical CBOR, bound collection/text lengths and
nesting, reject duplicate keys according to the chosen strict policy, and validate
COSE EC2/P-256/alg=-25 keys before constructing SEC1 agreement points. Request
models retain absent versus empty allow/exclude lists and absent versus explicit
UV options. Preserve the exact encoded credential-management subCommandParams
bytes for MAC verification instead of re-encoding a subset of decoded fields.
Do not log requests containing account or PIN information.

## Required state

The backend still needs durable credential creation/replacement/deletion, actual
PIN verification and persistent retries, token issuance and expiry, permission/RP
binding, getNextAssertion and enumeration continuations, cancellation/timeouts,
and explicit reset behavior. Storage read/crypto failures must not turn into an
empty credential database, unset PIN, or reset retry counter. Cancellation must
not drop in-progress flash writes. Serial pairing/backup grants remain separate
from CTAP permissions; no CTAP permission here authorizes secret export.

Permissions::from_bits rejects zero, rejects defined permissions for absent
features, and ignores undefined bits. A mask is only requested permissions; it
does not authorize a command. A request containing only undefined bits can
produce an empty effective mask and must not authorize any operation.

Generate `HmacSecret` once per credential using the hardware-seeded CSPRNG.
Persist its 64-byte storage encoding inside the encrypted credential and reload
it unchanged; loss or regeneration changes PRF output. Store the effective
CredProtect policy with the credential as well. AssertionEvidence is supplied by
the trusted backend after real UP/UV checks; it is not decoded from the client.
The helper verifies salt authentication before CBC decryption, enforces one or
two 32-byte salts, selects the correct UV seed, and returns only encrypted output.
Temporary secrets and failed output are zeroized. A missing seed must be handled
by the command algorithm rather than silently generating a replacement.

## Requirement basis and checks

The baseline is [CTAP 2.3 Proposed Standard, February 26, 2026](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html),
sections 6, 8, 9, 12.1, and 12.7. Section 9 makes hmac-secret mandatory for
FIDO_2_3, and requires additional features depending on discoverability and user
verification. This profile uses ClientPIN and credentialManagement instead of a
biometric sensor or a built-in account-management UI, and includes protocol 2.
The optional minPinLength and enterprise-attestation features are not advertised,
so their conditional authenticatorConfig subcommands are outside this scope.

Host tests import the actual modules and exercise permission parsing, dispatch
and failure cleanup, credential protection, algorithm preferences, and hmac-secret
with Python-generated HMAC fixtures, both UV modes, one/two salts, persistence,
tampering, and malformed inputs. A recording backend tests routing only; it does
not implement CTAP command semantics.

```sh
cd firmware
cargo test -p doohickey-crypto --test ctap --target x86_64-unknown-linux-gnu
```

Use the appropriate host target on macOS/ARM Linux as described in the crypto
guide. Full interoperability/conformance testing belongs after backend and
transport integration; these module tests do not establish compliance.
