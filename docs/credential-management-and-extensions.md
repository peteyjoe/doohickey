# Credential management and extensions

The operational development profile exposes `credMgmt=true`, `credProtect` and
`hmac-secret`. It still reports FIDO_2_0; this is not a claim of full CTAP 2.3
conformance. Physical and lengthy Python qualification are deferred.

## PIN-authorized management

`ctap::management` implements authenticatorCredentialManagement (`0x0a`):

| Subcommand | Behavior |
| --- | --- |
| 1 | Resident credential count and estimated remaining capacity |
| 2 / 3 | Begin/continue RP enumeration, with full RP IDs and hashes |
| 4 / 5 | Begin/continue credential enumeration for one RP |
| 6 | Delete a committed resident credential |
| 7 | Update the credential's user name/display name |

Credential responses include the user entity, descriptor, public COSE key and
credProtect level. Total counts appear only in begin responses. Enumeration
only visits committed directory members, never retired or unpublished records.
User updates require the existing opaque user ID; they cannot change identity,
signing keys, counters, protection policies or HMAC seeds. Absent/empty labels
are removed; UTF-8 names truncate at a character boundary to 64 bytes.

The client obtains a protocol-2 token with CM permission (`0x04`). Metadata and
enumeration require an unbound token. Deletion and updates also accept an
RP-bound CM token if its RP matches the credential. Combined grants containing
MC/GA still require an RP ID. Legacy token retrieval grants the implemented
default permissions, with RP binding applied on credential authorization.

Authenticated commands verify HMAC over `subCommand || original CBOR params`,
including unknown members of the canonical parameter map. Missing auth is
PUAT_REQUIRED; unsupported protocol, bad MAC, missing permission and wrong RP
never confer access. Next calls use only the previously authorized cursor and
grant; their caller-supplied parameters cannot switch RP or enumeration kind.

Cursors are channel/session bound, expire after 30 seconds, and require the
original CM token to remain valid. The token's fixed 30-second deadline can end
a sequence sooner than its cursor timeout. Another command, errors, cancellation,
channel switching, resynchronization, disconnect and reboot discard cursors.
Expiry is checked again before returning results and before management writes.
No physical touch is substituted for a missing PIN authorization.

Deletion uses the existing directory commit/tombstone mechanism. Label updates
are one authenticated record write with readback. An uncertain acknowledgement
may mean the mutation committed; callers should re-enumerate. Storage errors
do not become an empty credential database or a successful mutation.

Capacity remains bounded by the existing fourteen-entry RP-hash directories.
The reported remaining count is an estimate bounded by directory capacity and
flash geometry; log overhead, legacy records, tombstones and orphaned records
can cause KeyStoreFull earlier. RP enumeration uses a bounded cursor scan, not
an in-RAM list of the entire database. Large databases may need scan/cache
optimization during qualification.

## Persistent extensions

New operational credentials use a 727-byte `DOOHCR03` plaintext, encrypted with
the existing Credential kind and replaceable credential key. Existing 202-byte
`DOOHCR01` and 660-byte `DOOHCR02` records remain readable without migration.
The original ID and field offsets are retained; extension fields are:

| Offset | Meaning |
| --- | --- |
| 660 | Effective credProtect policy, 1..3 |
| 661 | HMAC seeds present flag |
| 662..725 | CredRandomWithUV (32 bytes), then CredRandomWithoutUV (32 bytes) |
| 726 | Resident marker, 0 or 1 |

New credentials generate both seeds using the hardware-seeded CSPRNG even when
creation did not request hmac-secret. Seeds persist unchanged through reboots,
updates, counters and label changes. Resident records, including seeds and policy,
are authenticated/read back before the directory commit. Legacy records have
policy 1 and no seeds; they never silently acquire regenerated PRF secrets.
Deletion clears seeds in the latest tombstone, but does not securely erase
historical encrypted flash entries. Rollback protection remains unimplemented.

`credProtect` is returned only if requested at creation. Policy 1 permits normal
selection; policy 2 requires UV for discovery but permits an explicit allow-list
ID without UV; policy 3 requires actual UV even with an allow list. Ineligible
credentials disappear from applicable-credential counts. Exclusions follow the
separate CTAP rule: policy 3 does not disclose existence without UV. Continuation
responses retain the original verified evidence and eligible account set.

`hmac-secret` creation returns true only when requested. Assertions accept
explicit protocol 2, valid P-256 agreement keys, one/two encrypted 32-byte salts,
and a 32-byte saltAuth. Salt authentication precedes decryption and counter
updates. Requests with up=false are rejected. The verified UV result selects
the seed; the client cannot select it independently. Only encrypted HMAC output
is returned, inside signed authenticatorData with ED set. There is no plaintext
secret export. Legacy credentials omit HMAC output, rather than changing their
secrets. Continuations own bounded copies of the original extension input and
apply it to each selected credential's own seeds.

Only these two extensions are advertised. hmac-secret-mc, credBlob, large blobs
and built-in UV remain unsupported. [Reset, recovery and upgrade policy](reset-and-upgrades.md)
are implemented. Secure boot, serial backup authorization and complete CTAP 2.3
qualification remain separate.

## Focused checks

```sh
cd firmware
cargo test --locked -p doohickey-crypto --test credential_repository --target x86_64-unknown-linux-gnu
cargo clippy --locked --release -- -D warnings
```

Focused tests cover exact MAC input, permission/RP restrictions, enumeration
scope/expiry, deletion, immutable user IDs, capacity failures, label updates,
legacy compatibility, protection filtering, signed creation/assertion outputs,
stable UV-specific PRFs, salt tampering and extension continuations. Hardware
and cross-client interoperability evidence must be recorded separately.

Basis: [CTAP 2.3 sections 6.8, 12.1 and 12.7](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html).
