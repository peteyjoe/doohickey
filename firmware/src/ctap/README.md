# CTAP module foundation

`crate::ctap` is the protocol layer; `crate::crypto::ctap` remains the portable
cryptographic implementation. The selected target is ES256, discoverable and
non-discoverable credentials, ClientPIN with protocol 2, credential management,
`credProtect`, and `hmac-secret`. No biometric, large-blob, enterprise-attestation,
authenticator-config, or vendor backup modules are added in this step.

This is **not yet a working CTAP authenticator**. The typed command boundary,
dispatch, algorithm selection, permission parsing, credential-protection filter,
and protocol-2 hmac-secret helper are implemented. Bounded CBOR/COSE decoding
and canonical getInfo encoding are connected to [USB HID](../usb/README.md).
The stateful command algorithms, durable credential/PIN storage, user-presence
integration, and command deadlines are not connected. The default discovery
backend returns InvalidCommand for structurally valid unfinished commands;
malformed requests return decoding errors. TARGET_* constants describe
the intended profile, not the discovery response or a compliance claim.
The main application runs startup inspection before USB transport, then
supports local button-confirmed base initialization. This provisions a root only
under the selected OTP build policy and prepares settings/credential key; it
does not implement CTAP credential operations. The [alpha roadmap](../../../docs/alpha-roadmap.md) tracks
the application algorithms and qualification still required.

## Modules

| File | Responsibility |
| --- | --- |
| `mod.rs` | Module entry and target profile constants |
| `cbor.rs` | Canonical validation, borrowed views and fixed-buffer encoder |
| `codec.rs` | Bounded command decoding into typed requests and fixed scratch arrays |
| `info.rs` | Read-only development getInfo response |
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

`codec::decode` accepts the command byte followed by its CBOR parameters. It
borrows strings and bytes from the input and list slots/SEC1 points from
`codec::Scratch`. The input and scratch must outlive the request. The entire
document is validated before any unknown fields are ignored. Credential-management
subCommandParams retain their exact original canonical bytes for MAC verification,
including unknown members. Absent versus empty lists/auth parameters and explicit
UV/rk options remain distinguishable. COSE agreement keys must be EC2/P-256,
alg=-25 with 32-byte coordinates and a valid curve point.

| Bound | Limit |
| --- | --- |
| Full command, including command byte | 1024 bytes |
| Container nesting | 4 maps/arrays |
| Total CBOR items, including keys | 256 |
| Members/elements per map/array | 32 |
| Allow/exclude descriptors | 8 |
| Credential algorithm preferences | 16 |
| Attestation format preferences | 8 |

Lengths use checked arithmetic and never control allocation. The strict policy
rejects nonminimal integers/lengths, duplicate or unsorted map keys, tags,
indefinite lengths, invalid UTF-8, trailing data, and excessive nesting with
InvalidCbor. Key ordering uses CTAP's major-type/encoded-length/byte ordering,
not RFC 8949 length-first ordering. Complex map keys are unsupported. Float
widths are retained as required by CTAP. Size/item/collection limits return
RequestTooLarge; wrong field types return CborUnexpectedType; missing top-level
required parameters return MissingParameter. Command-specific authorization,
policy, value lengths and normative error precedence still belong in handlers.
Do not log requests containing account or PIN information.

## Development getInfo

`usb::cbor::DiscoveryBackend` decodes synchronously and retains only a pending
getInfo bit. It never retains request references after HID clears the receive
buffer. Future asynchronous/stateful adapters must own copied request bytes.
Discovery works in every initialization state and does not access secrets or
write storage. The transport prefixes the canonical response with status OK.

The current response contains versions `["FIDO_2_0"]`, model AAGUID
`DOOHICKEY-DEV001` (16 bytes, shared across flash sizes), options
`rk=false, up=false, plat=false`, maxMsgSize `1024`, and transports `["usb"]`.
It omits extensions, PIN protocols, algorithms, clientPin and uv. In particular,
clientPin=false would mean supported but unset, so it is not reported.
FIDO_2_0 is a development discovery baseline, not a claim that credential
operations or a conformant FIDO 2.0 authenticator are implemented. Do not publish
FIDO_2_3 or TARGET_* capabilities until their complete backend is implemented.
Serial `ctap_ready` remains false. Select a release AAGUID/attestation policy
before shipping; this development identifier is not a per-device identity.

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
and failure cleanup, bounded/canonical decoding, golden getInfo bytes and HID
integration, credential protection, algorithm preferences, and hmac-secret
with Python-generated HMAC fixtures, both UV modes, one/two salts, persistence,
tampering, and malformed inputs. A recording backend tests routing only; it does
not implement CTAP command semantics.

```sh
cd firmware
cargo test -p doohickey-crypto --test ctap --target x86_64-unknown-linux-gnu
cargo test -p doohickey-crypto --test ctap_codec --test usb --target x86_64-unknown-linux-gnu
```

Use the appropriate host target on macOS/ARM Linux as described in the crypto
guide. Full interoperability/conformance testing belongs after backend and
transport integration; these module tests do not establish compliance.
