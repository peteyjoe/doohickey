# Discoverable credentials

The operational GetInfo profile reports `rk=true`. `makeCredential` with
`rk=true` stores a discoverable ES256 credential; `rk=false` retains the original
allow-list-only behavior. PIN authorization, fresh physical presence, exclusion
checks and durable counters apply as before. This is still a development
FIDO_2_0 profile, not the complete CTAP 2.3 implementation.

An assertion without an allow list looks up accounts by rpIdHash and returns
the newest account first. Its user entity includes the opaque user handle.
Names/display names are returned only if the original assertion verified a PIN
token; they are suppressed without UV. An allow-list response continues to omit
user information. Non-discoverable credentials are never included in discovery.

When multiple accounts match, the first response includes numberOfCredentials.
`getNextAssertion` returns each remaining account once, with the original client
hash and UP/UV evidence and a newly persisted counter/signature. It does not
ask for another touch or include numberOfCredentials. The sequence expires
after 30 seconds since the last successful response, and clears on another
command, malformed requests, cancellation, channel changes, resynchronization,
disconnect or reboot. Exhausted/expired sequences return NotAllowed.

## Persistent formats and commit behavior

Existing 202-byte `DOOHCR01` records and 60-byte IDs remain readable and unchanged.
New resident records use `DOOHCR02` and a 660-byte plaintext. Offsets 9..202
retain the original ID/rpIdHash/user handle/private scalar/counter encoding.
Byte 8 is 2 for an active resident credential and 0 for a tombstone.

| Offset | Bytes | Additional resident fields |
| --- | --- | --- |
| 202 | 1 + 64 | User name byte length and zero-padded UTF-8 |
| 267 | 1 + 64 | Display name byte length and zero-padded UTF-8 |
| 332 | 2 + 253 | RP ID LE16 length and zero-padded UTF-8 |
| 587 | 1 + 64 | RP name byte length and zero-padded UTF-8 |
| 652 | 8 | Reserved zero bytes |

Names truncate at a UTF-8 boundary to 64 bytes. RP IDs are limited to 253 bytes.
Records still use the credential encryption kind and key/address-bound AAD.

Encrypted directories occupy `0x03000000..=0x030000ff`, selected by the first
byte of rpIdHash. A directory plaintext is 865 bytes: `DOOHRK01`, 16 random
state bytes, a u8 entry count, and fourteen zero-padded 60-byte ID slots. It uses
the Configuration encryption kind. Every referenced record authenticates before
being used. These keys/formats must not be reused or changed in place.

**Bound:** each directory can hold 14 accounts, shared by all RPs in that hash
bucket. A full bucket returns KeyStoreFull even if other buckets have space.
Replacing an existing account works at this limit. Physical flash capacity can
be reached sooner; both firmware sizes use the same directory bound. A paged
directory can extend this later with explicit format compatibility.

Creation prepares and reads back the new record before committing its ID in one
directory write. Re-registering the same RP/user handle removes the old ID and
appends the new ID in that same commit. Both discovery and allow-list lookup
reject the retired ID, although its old encrypted record remains in flash.
Deletion commits directory removal before writing a tombstone. A failed write
may leave either the old or new committed account; it does not require an index
repair that would silently reset user data. An uncertain creation can leave an
unpublished record consuming space. A valid resident ID with a missing/corrupt
directory fails closed; a valid but retired ID returns no match.

There is no rollback protection or secure erasure. Restoring an old valid
directory can restore old accounts. Do not downgrade to firmware unaware of the
resident format. Credential management and extension integration are now implemented; see
[management and extensions](credential-management-and-extensions.md). Reset and
physical qualification remain separate work.

## Focused development checks

```sh
cd firmware
cargo test --locked -p doohickey-crypto --test credential_repository --target x86_64-unknown-linux-gnu
cargo clippy --locked --release -- -D warnings
```

Tests cover legacy compatibility, reconstruction, same-account replacement,
directory write failures before/after commit, deletion, capacity, UTF-8,
ordering, UV privacy, continuation exhaustion/timeout and invalidation.
Lengthy Python interoperability and physical validation are deferred.

The existing credential tool accepts `register --resident` (plus `--pin` when a
PIN is configured). Its authentication path still uses the saved allow-list ID;
use a discoverable WebAuthn/FIDO client for the no-allow-list flow when validation
resumes. See [the credential guide](credential-milestone.md) for the Python setup.

Basis: [CTAP makeCredential, getAssertion and getNextAssertion](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential).
