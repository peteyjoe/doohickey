# CTAP module foundation

`crate::ctap` is the protocol layer; `crate::crypto::ctap` remains the portable
cryptographic implementation. The selected target is ES256, discoverable and
non-discoverable credentials, ClientPIN with protocol 2, credential management,
`credProtect`, and `hmac-secret`. No biometric, large-blob, enterprise-attestation,
authenticator-config, or vendor backup modules are added in this step.

The firmware now implements the development ES256 registration, discoverable-account
and allow-list assertion flows, including packed self-attestation, encrypted
persistence, durable signature counters and fresh physical button confirmation.
It advertises FIDO_2_0 with UP, ES256, a 1024-byte limit, 8 list entries and
60-byte credential IDs, dynamic clientPin, pinUvAuthToken and protocol [2]. Protocol-2 ClientPIN, PIN-based UV and discoverable credentials are implemented;
credential management and extensions remain unavailable;
TARGET_* constants describe the future CTAP 2.3 profile, not current capabilities.
See [credential persistence and the update test](../../../docs/credential-milestone.md)
for the operational profile, persistent format, limitations and test commands.

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

## Runtime ownership and remaining state

`application.rs` owns the coordinator, repository, RNG and physical inputs.
`usb::cbor::AuthenticatorBackend` forwards copied requests through the bounded
`ctap::exchange::Exchange`; `authenticator::execute` handles the current profile.
No borrow of mailbox state spans an await. Cancellation/disconnect requests
completion at safe points and discards obsolete output, never drops flash I/O.
The standalone `DiscoveryBackend` remains a read-only, unavailable-profile adapter;
its getInfo uses up=false. Main uses the operational adapter after initialization
and entropy succeed; serial ctap_ready reflects that availability.

ClientPIN implements protocol 2, persistent retries, scoped expiring RAM tokens
and PIN-based UV; see [the PIN guide](../../../docs/client-pin.md). Discoverable credentials and getNextAssertion are implemented; see the
[format and limits](../../../docs/discoverable-credentials.md). The target profile
still needs credential management, extension integration and reset. It remains a development build,
not a full CTAP 2.3 implementation or compliance claim.

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
