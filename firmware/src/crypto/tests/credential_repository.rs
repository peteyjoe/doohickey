#![allow(dead_code, unused_imports)]
#[path = "../../ctap/authenticator.rs"]
mod authenticator;
#[path = "../../ctap/mod.rs"]
mod ctap;
#[path = "../../ctap/pin_session.rs"]
mod pin_session;
#[path = "support/credential_storage.rs"]
mod storage;
// The authenticator's parent is the test crate instead of firmware::ctap.
use ctap::{Request, Result, Status, cbor, credentials, info, pin_uv};
use doohickey_crypto::{ctap::sha256, secrets::MasterKey};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use storage::credentials::{Error, ID_SIZE, Repository};
use zeroize::Zeroizing;

fn ready<F: core::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cx = core::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut cx) {
        core::task::Poll::Ready(value) => value,
        _ => panic!("unexpected pending test I/O"),
    }
}
fn key() -> MasterKey {
    MasterKey::from_bytes(Zeroizing::new([7; 32]))
}

fn agreement(
    repo: &mut Repository<'_, '_, '_, '_, ChaCha20Rng>,
    session: &mut pin_session::Session,
) -> (doohickey_crypto::ctap::PinUvSharedSecret, [u8; 65]) {
    use doohickey_crypto::ctap::{PinUvKeyAgreement, PinUvProtocol};
    let mut out = [0; 512];
    let n = ready(session.handle(
        repo,
        pin_uv::Request::GetKeyAgreement { protocol: 2 },
        0,
        &mut out,
    ))
    .unwrap();
    let cose = cbor::decode(&out[..n])
        .unwrap()
        .get_int(1)
        .unwrap()
        .unwrap();
    let mut point = [0; 65];
    point[0] = 4;
    point[1..33].copy_from_slice(cose.get_int(-2).unwrap().unwrap().bytes().unwrap());
    point[33..].copy_from_slice(cose.get_int(-3).unwrap().unwrap().bytes().unwrap());
    let mut random = ChaCha20Rng::from_seed([25; 32]);
    let client = PinUvKeyAgreement::generate(&mut random);
    (
        client.agree(&point, PinUvProtocol::Two).unwrap(),
        client.public_key(),
    )
}
fn set_pin(
    repo: &mut Repository<'_, '_, '_, '_, ChaCha20Rng>,
    session: &mut pin_session::Session,
    pin: &[u8],
) -> Result<usize> {
    let (shared, point) = agreement(repo, session);
    let mut padded = [0; 64];
    padded[..pin.len()].copy_from_slice(pin);
    let mut encrypted = [0; 80];
    let mut random = ChaCha20Rng::from_seed([26; 32]);
    shared
        .encrypt(&mut random, &padded, &mut encrypted)
        .unwrap();
    let mut tag = [0; 32];
    shared.authenticate(&encrypted, &mut tag).unwrap();
    ready(session.handle(
        repo,
        pin_uv::Request::SetPin {
            protocol: 2,
            key_agreement: &point,
            new_pin_enc: &encrypted,
            pin_uv_auth_param: &tag,
        },
        0,
        &mut [0; 512],
    ))
}
fn token(
    repo: &mut Repository<'_, '_, '_, '_, ChaCha20Rng>,
    session: &mut pin_session::Session,
    pin: &[u8],
    now: u64,
) -> Result<[u8; 32]> {
    let (shared, point) = agreement(repo, session);
    let mut encrypted = [0; 32];
    let mut random = ChaCha20Rng::from_seed([27; 32]);
    shared
        .encrypt(&mut random, &sha256(pin)[..16], &mut encrypted)
        .unwrap();
    let mut out = [0; 512];
    let n = ready(session.handle(
        repo,
        pin_uv::Request::GetTokenWithPermissions {
            protocol: 2,
            key_agreement: &point,
            pin_hash_enc: &encrypted,
            permissions: pin_uv::Permissions::from_bits(3).unwrap(),
            rp_id: Some("example.com"),
        },
        now,
        &mut out,
    ))?;
    let bytes = cbor::decode(&out[..n])
        .unwrap()
        .get_int(2)
        .unwrap()
        .unwrap()
        .bytes()
        .unwrap();
    let mut key = [0; 32];
    assert_eq!(shared.decrypt(bytes, &mut key).unwrap(), 32);
    Ok(key)
}
#[test]
fn client_pin_persists_scopes_tokens_expires_and_blocks_wrong_pin() {
    use doohickey_crypto::ctap::hmac_sha256;
    let mut store = storage::Storage::default();
    let master = key();
    let mut random = rng();
    let mut session = pin_session::Session::default();
    let mut repo = Repository::new(&mut store, &master, &mut random);
    assert_eq!(set_pin(&mut repo, &mut session, b"1234"), Ok(0));
    assert_eq!(
        set_pin(&mut repo, &mut session, b"5678"),
        Err(Status::PinAuthInvalid)
    );
    let key = token(&mut repo, &mut session, b"1234", 100).unwrap();
    let tag = hmac_sha256(&key, &[7; 32]);
    let auth = pin_uv::AuthParameters {
        protocol: Some(2),
        parameter: Some(&tag),
    };
    assert_eq!(
        session.authorize(
            &auth,
            &sha256(b"wrong.rp"),
            &[7; 32],
            pin_uv::Permission::MakeCredential,
            101
        ),
        Err(Status::PinAuthInvalid)
    );
    assert_eq!(
        session.authorize(
            &auth,
            &sha256(b"example.com"),
            &[7; 32],
            pin_uv::Permission::MakeCredential,
            101
        ),
        Ok(true)
    );
    assert_eq!(
        session.authorize(
            &auth,
            &sha256(b"example.com"),
            &[7; 32],
            pin_uv::Permission::CredentialManagement,
            101
        ),
        Err(Status::PinAuthInvalid)
    );
    assert_eq!(
        session.authorize(
            &auth,
            &sha256(b"example.com"),
            &[7; 32],
            pin_uv::Permission::MakeCredential,
            30100
        ),
        Err(Status::PinAuthInvalid)
    );
    for expected in [
        Status::PinInvalid,
        Status::PinInvalid,
        Status::PinAuthBlocked,
        Status::PinAuthBlocked,
    ] {
        assert_eq!(token(&mut repo, &mut session, b"wrong", 0), Err(expected));
    }
    drop(repo);
    let mut session = pin_session::Session::default();
    let mut repo = Repository::new(&mut store, &master, &mut random);
    assert_eq!(ready(session.load(&mut repo)).unwrap().unwrap()[24], 5);
    assert!(token(&mut repo, &mut session, b"1234", 0).is_ok());
    assert_eq!(ready(session.load(&mut repo)).unwrap().unwrap()[24], 8);
}
fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([3; 32])
}
fn address(id: &[u8]) -> u32 {
    u32::from_le_bytes(id[8..12].try_into().unwrap())
}
fn fixture(store: &mut storage::Storage<'_>) -> ([u8; ID_SIZE], [u8; 65]) {
    let mut rng = rng();
    let key = key();
    let mut repo = Repository::new(store, &key, &mut rng);
    let credential = ready(repo.create(&sha256(b"example.com"), b"test-user")).unwrap();
    (*credential.id(), credential.public_key().unwrap())
}
#[test]
fn encrypted_records_survive_reconstruction_and_counter_updates() {
    let mut store = storage::Storage::default();
    let (id, public) = fixture(&mut store);
    let envelope = &store.values[&address(&id)];
    assert!(!envelope.windows(9).any(|w| w == b"test-user"));
    assert!(!envelope.windows(16).any(|w| w == &id[..16]));
    let mut rng = ChaCha20Rng::from_seed([9; 32]);
    let key = key();
    let mut repo = Repository::new(&mut store, &key, &mut rng);
    let mut credential = ready(repo.read(&id, &sha256(b"example.com")))
        .unwrap()
        .unwrap();
    assert_eq!(credential.public_key().unwrap(), public);
    assert_eq!(credential.user_id(), b"test-user");
    assert_eq!(ready(repo.advance_counter(&mut credential)), Ok(1));
    drop(repo);
    let mut repo = Repository::new(&mut store, &key, &mut rng);
    let mut credential = ready(repo.read(&id, &sha256(b"example.com")))
        .unwrap()
        .unwrap();
    assert_eq!(credential.counter(), 1);
    assert_eq!(ready(repo.advance_counter(&mut credential)), Ok(2));
}
#[test]
fn foreign_ids_and_other_rps_do_not_access_storage_but_missing_owned_records_fail_closed() {
    let mut store = storage::Storage::default();
    let (id, _) = fixture(&mut store);
    let before = store.reads;
    let key = key();
    let mut rng = rng();
    {
        let mut repo = Repository::new(&mut store, &key, &mut rng);
        assert!(
            ready(repo.read(&id, &sha256(b"other.example")))
                .unwrap()
                .is_none()
        );
        for i in 0..id.len() {
            let mut changed = id;
            changed[i] ^= 1;
            assert!(
                ready(repo.read(&changed, &sha256(b"example.com")))
                    .unwrap()
                    .is_none()
            );
        }
    }
    assert_eq!(store.reads, before);
    store.values.remove(&address(&id));
    let mut repo = Repository::new(&mut store, &key, &mut rng);
    assert!(matches!(
        ready(repo.read(&id, &sha256(b"example.com"))),
        Err(Error::Integrity)
    ));
}
#[test]
fn every_tampered_or_truncated_envelope_fails_and_wrong_key_cannot_use_ids() {
    let mut store = storage::Storage::default();
    let (id, _) = fixture(&mut store);
    let original = store.values[&address(&id)].clone();
    let key = key();
    let mut rng = rng();
    for i in 0..original.len() * 2 {
        let changed = if i < original.len() {
            original[..i].to_vec()
        } else {
            let mut v = original.clone();
            v[i - original.len()] ^= 1;
            v
        };
        store.values.insert(address(&id), changed);
        let mut repo = Repository::new(&mut store, &key, &mut rng);
        assert!(matches!(
            ready(repo.read(&id, &sha256(b"example.com"))),
            Err(Error::Integrity)
        ));
    }
    store.values.insert(address(&id), original);
    let other = MasterKey::from_bytes(Zeroizing::new([8; 32]));
    let mut repo = Repository::new(&mut store, &other, &mut rng);
    assert!(
        ready(repo.read(&id, &sha256(b"example.com")))
            .unwrap()
            .is_none()
    );
}
#[test]
fn user_replacement_and_tombstone_preserve_identity_and_do_not_recreate_deleted_keys() {
    let mut store = storage::Storage::default();
    let (id, public) = fixture(&mut store);
    let key = key();
    let mut rng = rng();
    let rp = sha256(b"example.com");
    let mut repo = Repository::new(&mut store, &key, &mut rng);
    ready(repo.update_user(&id, &rp, b"replacement")).unwrap();
    let r = ready(repo.read(&id, &rp)).unwrap().unwrap();
    assert_eq!(r.public_key().unwrap(), public);
    assert_eq!(r.user_id(), b"replacement");
    assert_eq!(ready(repo.delete(&id, &rp)), Ok(true));
    assert!(ready(repo.read(&id, &rp)).unwrap().is_none());
    assert_eq!(ready(repo.delete(&id, &rp)), Ok(false));
    assert_eq!(
        ready(repo.update_user(&id, &rp, b"new")),
        Err(Error::NotFound)
    );
    assert_eq!(store.values.len(), 1); // Authenticated tombstone remains.
}

#[test]
fn persistent_format_is_pinned_and_counter_exhaustion_never_wraps() {
    let mut store = storage::Storage::default();
    let (id, _) = fixture(&mut store);
    let key = key();
    let mut rng = rng();
    let mut plaintext = [0; 202];
    {
        let mut encrypted = storage::encrypted::EncryptedStorage::new(&mut store, &key, &mut rng);
        assert_eq!(
            ready(encrypted.read(
                address(&id),
                storage::encrypted::RecordKind::Credential,
                &mut plaintext
            ))
            .unwrap(),
            Some(202)
        );
        assert_eq!(&plaintext[..8], b"DOOHCR01");
        assert_eq!(plaintext[8], 1);
        assert_eq!(&plaintext[9..69], &id);
        assert_eq!(&plaintext[69..101], &sha256(b"example.com"));
        assert_eq!(plaintext[101], 9);
        assert_eq!(&plaintext[102..111], b"test-user");
        plaintext[198..202].copy_from_slice(&u32::MAX.to_le_bytes());
        ready(encrypted.store(
            address(&id),
            storage::encrypted::RecordKind::Credential,
            &plaintext,
        ))
        .unwrap();
    }
    let writes = store.writes;
    let mut repo = Repository::new(&mut store, &key, &mut rng);
    let mut c = ready(repo.read(&id, &sha256(b"example.com")))
        .unwrap()
        .unwrap();
    assert_eq!(
        ready(repo.advance_counter(&mut c)),
        Err(Error::CounterExhausted)
    );
    assert_eq!(store.writes, writes);
}
#[test]
fn interrupted_mutations_are_old_or_new_and_acknowledgement_loss_never_reuses_a_count() {
    for after in [false, true] {
        let mut store = storage::Storage::default();
        let (id, public) = fixture(&mut store);
        store.fail_before = !after;
        store.fail_after = after;
        let key = key();
        let mut rng = rng();
        let rp = sha256(b"example.com");
        let mut repo = Repository::new(&mut store, &key, &mut rng);
        let mut c = ready(repo.read(&id, &rp)).unwrap().unwrap();
        assert_eq!(ready(repo.advance_counter(&mut c)), Err(Error::Io));
        assert_eq!(c.counter(), 0);
        drop(repo);
        store.fail_before = false;
        store.fail_after = false;
        let mut repo = Repository::new(&mut store, &key, &mut rng);
        let mut c = ready(repo.read(&id, &rp)).unwrap().unwrap();
        assert_eq!(c.counter(), u32::from(after));
        assert_eq!(c.public_key().unwrap(), public);
        assert_eq!(
            ready(repo.advance_counter(&mut c)),
            Ok(if after { 2 } else { 1 })
        );
        drop(repo);
        store.fail_before = !after;
        store.fail_after = after;
        let mut repo = Repository::new(&mut store, &key, &mut rng);
        assert_eq!(ready(repo.delete(&id, &rp)), Err(Error::Io));
        drop(repo);
        store.fail_before = false;
        store.fail_after = false;
        let mut repo = Repository::new(&mut store, &key, &mut rng);
        assert_eq!(ready(repo.read(&id, &rp)).unwrap().is_none(), after);
    }
}
struct FailRng {
    calls: usize,
    fail: usize,
    inner: ChaCha20Rng,
}
impl RngCore for FailRng {
    fn next_u32(&mut self) -> u32 {
        panic!("fallible RNG required")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("fallible RNG required")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("fallible RNG required")
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.calls += 1;
        if self.calls == self.fail {
            return Err(rand_core::Error::from(
                core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
            ));
        }
        self.inner.try_fill_bytes(out)
    }
}
impl CryptoRng for FailRng {}
#[test]
fn entropy_failure_at_key_id_and_nonce_steps_never_persists_a_credential() {
    for fail in 1..=3 {
        let mut store = storage::Storage::default();
        let key = key();
        let mut rng = FailRng {
            calls: 0,
            fail,
            inner: rng(),
        };
        let mut repo = Repository::new(&mut store, &key, &mut rng);
        assert!(matches!(
            ready(repo.create(&[1; 32], b"user")),
            Err(Error::Entropy)
        ));
        assert!(store.values.is_empty());
    }
}

struct Presence {
    result: Result<()>,
    calls: usize,
    cancelled: bool,
}
impl Default for Presence {
    fn default() -> Self {
        Self {
            result: Ok(()),
            calls: 0,
            cancelled: false,
        }
    }
}
impl authenticator::Presence for Presence {
    async fn confirm(&mut self) -> Result<()> {
        self.calls += 1;
        self.result
    }
    fn cancelled(&self) -> bool {
        self.cancelled
    }
}
fn make_wire() -> Vec<u8> {
    hex_literal::hex!(
        "01 a4 01 5820 0000000000000000000000000000000000000000000000000000000000000000
      02 a1 626964 6b6578616d706c652e636f6d 03 a1 626964 4101
      04 81 a2 63616c67 26 6474797065 6a7075626c69632d6b6579"
    )
    .to_vec()
}
fn assertion_wire(id: &[u8], rp: &str, up: bool) -> Vec<u8> {
    let mut out = vec![2, 0xa4, 1, 0x60 + rp.len() as u8];
    out.extend(rp.bytes());
    out.extend([2, 0x58, 32]);
    out.extend([9; 32]);
    out.extend([3, 0x81, 0xa2, 0x62, b'i', b'd', 0x58, id.len() as u8]);
    out.extend(id);
    out.extend(b"\x64type\x6apublic-key\x05\xa1\x62up");
    out.push(if up { 0xf5 } else { 0xf4 });
    out
}
fn call(store: &mut storage::Storage<'_>, wire: &[u8], presence: &mut Presence) -> Result<Vec<u8>> {
    let key = key();
    let mut rng = ChaCha20Rng::from_seed(sha256(&(store.writes as u64).to_le_bytes()));
    let mut repo = Repository::new(store, &key, &mut rng);
    let mut scratch = ctap::codec::Scratch::new();
    let request = ctap::codec::decode(wire, &mut scratch)?;
    let mut output = [0xa5; 1023];
    match ready(authenticator::execute(
        &mut repo,
        request,
        presence,
        &mut output,
    )) {
        Ok(n) => {
            assert!(cbor::decode(&output[..n]).is_ok());
            Ok(output[..n].to_vec())
        }
        Err(e) => {
            assert_eq!(output, [0; 1023]);
            Err(e)
        }
    }
}
fn registration(store: &mut storage::Storage<'_>) -> (Vec<u8>, VerifyingKey) {
    let result = call(store, &make_wire(), &mut Presence::default()).unwrap();
    let response = cbor::decode(&result).unwrap();
    assert_eq!(
        response.get_int(1).unwrap().unwrap().text().unwrap(),
        "packed"
    );
    let auth = response.get_int(2).unwrap().unwrap().bytes().unwrap();
    assert_eq!(&auth[..32], &sha256(b"example.com"));
    assert_eq!(auth[32], 0x41);
    assert_eq!(&auth[33..37], &[0; 4]);
    assert_eq!(&auth[37..53], b"DOOHICKEY-DEV001");
    let len = u16::from_be_bytes(auth[53..55].try_into().unwrap()) as usize;
    assert_eq!(len, ID_SIZE);
    let id = auth[55..55 + len].to_vec();
    let cose = cbor::decode(&auth[55 + len..]).unwrap();
    assert_eq!(cose.get_int(1).unwrap().unwrap().unsigned().unwrap(), 2);
    assert_eq!(cose.get_int(3).unwrap().unwrap().integer().unwrap(), -7);
    let mut point = vec![4];
    point.extend(cose.get_int(-2).unwrap().unwrap().bytes().unwrap());
    point.extend(cose.get_int(-3).unwrap().unwrap().bytes().unwrap());
    let public = VerifyingKey::from_sec1_bytes(&point).unwrap();
    let att = response.get_int(3).unwrap().unwrap();
    let signature =
        Signature::from_der(att.get_text("sig").unwrap().unwrap().bytes().unwrap()).unwrap();
    let mut message = auth.to_vec();
    message.extend([0; 32]);
    public.verify(&message, &signature).unwrap();
    (id, public)
}

#[test]
fn export_public_interoperability_fixture_when_requested() {
    let Some(path) = std::env::var_os("DOOHICKEY_INTEROP_FIXTURE") else {
        return;
    };
    let mut store = storage::Storage::default();
    let registration = call(&mut store, &make_wire(), &mut Presence::default()).unwrap();
    let map = cbor::decode(&registration).unwrap();
    let auth = map.get_int(2).unwrap().unwrap().bytes().unwrap();
    let id = &auth[55..115];
    let assertion = call(
        &mut store,
        &assertion_wire(id, "example.com", true),
        &mut Presence::default(),
    )
    .unwrap();
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    // Public messages only. No scalar, decrypted record or key is exported.
    std::fs::write(
        path,
        format!("{}\n{}\n", hex(&registration), hex(&assertion)),
    )
    .unwrap();
}
#[test]
fn make_assert_reboot_and_firmware_independent_reconstruction_verify_real_signatures() {
    let mut store = storage::Storage::default();
    let (id, public) = registration(&mut store);
    for (count, up) in [(1, true), (2, false), (3, true)] {
        let mut presence = Presence::default();
        let response = call(
            &mut store,
            &assertion_wire(&id, "example.com", up),
            &mut presence,
        )
        .unwrap();
        assert_eq!(presence.calls, usize::from(up));
        let map = cbor::decode(&response).unwrap();
        let auth = map.get_int(2).unwrap().unwrap().bytes().unwrap();
        assert_eq!(auth.len(), 37);
        assert_eq!(&auth[..32], &sha256(b"example.com"));
        assert_eq!(auth[32], u8::from(up));
        assert_eq!(u32::from_be_bytes(auth[33..].try_into().unwrap()), count);
        let signature =
            Signature::from_der(map.get_int(3).unwrap().unwrap().bytes().unwrap()).unwrap();
        let mut message = auth.to_vec();
        message.extend([9; 32]);
        public.verify(&message, &signature).unwrap();
        message[0] ^= 1;
        assert!(public.verify(&message, &signature).is_err());
        assert!(map.get_int(4).unwrap().is_none());
        assert!(map.get_int(5).unwrap().is_none());
    }
}
#[test]
fn denied_presence_wrong_rp_exclusion_and_cancellation_never_expose_success() {
    let mut store = storage::Storage::default();
    let mut denied = Presence {
        result: Err(Status::OperationDenied),
        ..Default::default()
    };
    assert!(matches!(
        call(&mut store, &make_wire(), &mut denied),
        Err(Status::OperationDenied)
    ));
    assert!(store.values.is_empty());
    let (id, _) = registration(&mut store);
    let writes = store.writes;
    assert!(matches!(
        call(
            &mut store,
            &assertion_wire(&id, "other.test", true),
            &mut Presence::default()
        ),
        Err(Status::NoCredentials)
    ));
    assert!(matches!(
        call(
            &mut store,
            &assertion_wire(&id, "example.com", true),
            &mut denied
        ),
        Err(Status::OperationDenied)
    ));
    let mut cancelled = Presence {
        cancelled: true,
        ..Default::default()
    };
    assert!(matches!(
        call(&mut store, &make_wire(), &mut cancelled),
        Err(Status::KeepaliveCancel)
    ));
    assert_eq!(store.writes, writes);
    let mut excluded = make_wire();
    excluded[1] = 0xa5;
    excluded.extend(b"\x05\x81\xa2\x62id\x58");
    excluded.push(id.len() as u8);
    excluded.extend(&id);
    excluded.extend(b"\x64type\x6apublic-key");
    let mut presence = Presence::default();
    assert!(matches!(
        call(&mut store, &excluded, &mut presence),
        Err(Status::CredentialExcluded)
    ));
    assert_eq!(presence.calls, 1);
    assert!(matches!(
        call(&mut store, &excluded, &mut denied),
        Err(Status::CredentialExcluded)
    ));
    assert_eq!(store.writes, writes);
}
#[test]
fn unsupported_options_are_errors_and_storage_failures_never_become_no_credentials() {
    let mut store = storage::Storage::default();
    for (suffix, status) in [
        (b"\x07\xa1\x62uv\xf5".as_slice(), Status::InvalidOption),
        (b"\x07\xa1\x62up\xf4".as_slice(), Status::InvalidOption),
        (b"\x08\x40".as_slice(), Status::PinNotSet),
    ] {
        let mut msg = make_wire();
        msg[1] = 0xa5;
        msg.extend(suffix);
        assert!(matches!(call(&mut store,&msg,&mut Presence::default()),Err(e)if e==status));
    }
    assert!(store.values.is_empty());
    let (id, _) = registration(&mut store);
    let writes = store.writes;
    store.fail_read = true;
    assert!(matches!(
        call(
            &mut store,
            &assertion_wire(&id, "example.com", true),
            &mut Presence::default()
        ),
        Err(Status::Other)
    ));
    store.fail_read = false;
    store.full = true;
    assert!(matches!(
        call(&mut store, &make_wire(), &mut Presence::default()),
        Err(Status::KeyStoreFull)
    ));
    store.full = false;
    assert!(store.writes > writes);
    store.values.remove(&address(&id));
    assert!(matches!(
        call(
            &mut store,
            &assertion_wire(&id, "example.com", true),
            &mut Presence::default()
        ),
        Err(Status::IntegrityFailure)
    ));
}

#[test]
fn client_pin_change_preserves_credentials_and_missing_state_is_not_unset() {
    let mut store = storage::Storage::default();
    let (id, public) = fixture(&mut store);
    let master = key();
    let mut random = rng();
    let mut repo = Repository::new(&mut store, &master, &mut random);
    let mut session = pin_session::Session::default();
    set_pin(&mut repo, &mut session, b"1234").unwrap();
    let (shared, point) = agreement(&mut repo, &mut session);
    let mut padded = [0; 64];
    padded[..5].copy_from_slice(b"56789");
    let mut client = rng();
    let mut new_enc = [0; 80];
    shared.encrypt(&mut client, &padded, &mut new_enc).unwrap();
    let mut old_enc = [0; 32];
    shared
        .encrypt(&mut client, &sha256(b"1234")[..16], &mut old_enc)
        .unwrap();
    let mut message = [0; 112];
    message[..80].copy_from_slice(&new_enc);
    message[80..].copy_from_slice(&old_enc);
    let mut tag = [0; 32];
    shared.authenticate(&message, &mut tag).unwrap();
    ready(session.handle(
        &mut repo,
        pin_uv::Request::ChangePin {
            protocol: 2,
            key_agreement: &point,
            new_pin_enc: &new_enc,
            pin_hash_enc: &old_enc,
            pin_uv_auth_param: &tag,
        },
        0,
        &mut [0; 512],
    ))
    .unwrap();
    assert!(token(&mut repo, &mut session, b"56789", 0).is_ok());
    assert_eq!(
        token(&mut repo, &mut session, b"1234", 0),
        Err(Status::PinInvalid)
    );
    assert_eq!(
        ready(repo.read(&id, &sha256(b"example.com")))
            .unwrap()
            .unwrap()
            .public_key()
            .unwrap(),
        public
    );
    drop(repo);
    store.values.remove(&0x0200_0000);
    let mut repo = Repository::new(&mut store, &master, &mut random);
    assert!(matches!(
        ready(session.load(&mut repo)),
        Err(Status::IntegrityFailure)
    ));
}
#[test]
fn client_pin_eight_attempts_survive_reboots_and_disconnect_does_not_clear_soft_block() {
    let mut store = storage::Storage::default();
    let master = key();
    let mut random = rng();
    let mut session = pin_session::Session::default();
    {
        let mut repo = Repository::new(&mut store, &master, &mut random);
        set_pin(&mut repo, &mut session, b"1234").unwrap();
    }
    for attempt in 0..8 {
        if attempt % 3 == 0 {
            session = pin_session::Session::default();
        }
        let mut repo = Repository::new(&mut store, &master, &mut random);
        let expected = if attempt == 7 {
            Status::PinBlocked
        } else if attempt % 3 == 2 {
            Status::PinAuthBlocked
        } else {
            Status::PinInvalid
        };
        assert_eq!(token(&mut repo, &mut session, b"bad", 0), Err(expected));
        assert_eq!(
            ready(session.load(&mut repo)).unwrap().unwrap()[24],
            7 - attempt
        );
        session.invalidate();
        if attempt % 3 == 2 {
            assert_eq!(
                token(&mut repo, &mut session, b"1234", 0),
                Err(Status::PinAuthBlocked)
            );
        }
    }
    session = pin_session::Session::default();
    let mut repo = Repository::new(&mut store, &master, &mut random);
    assert_eq!(
        token(&mut repo, &mut session, b"1234", 0),
        Err(Status::PinBlocked)
    );
}
#[test]
fn client_pin_uv_grant_is_used_for_credential_flags_and_is_single_use() {
    use doohickey_crypto::ctap::hmac_sha256;
    let mut store = storage::Storage::default();
    let master = key();
    let mut random = rng();
    let mut session = pin_session::Session::default();
    let mut repo = Repository::new(&mut store, &master, &mut random);
    set_pin(&mut repo, &mut session, b"1234").unwrap();
    let grant = token(&mut repo, &mut session, b"1234", 0).unwrap();
    let mut msg = make_wire();
    msg[1] = 0xa6;
    msg.extend([8, 0x58, 32]);
    msg.extend(hmac_sha256(&grant, &[0; 32]));
    msg.extend([9, 2]);
    for success in [true, false] {
        let mut scratch = ctap::codec::Scratch::new();
        let request = ctap::codec::decode(&msg, &mut scratch).unwrap();
        let mut out = [0xa5; 1023];
        let result = ready(authenticator::execute_with_session(
            &mut repo,
            request,
            &mut Presence::default(),
            &mut out,
            &mut session,
            0,
        ));
        if success {
            let n = result.unwrap();
            let auth = cbor::decode(&out[..n])
                .unwrap()
                .get_int(2)
                .unwrap()
                .unwrap()
                .bytes()
                .unwrap();
            assert_eq!(auth[32], 0x45);
        } else {
            assert_eq!(result, Err(Status::PinAuthInvalid));
            assert_eq!(out, [0; 1023]);
        }
    }
    let msg = make_wire();
    let mut scratch = ctap::codec::Scratch::new();
    let req = ctap::codec::decode(&msg, &mut scratch).unwrap();
    assert_eq!(
        ready(authenticator::execute_with_session(
            &mut repo,
            req,
            &mut Presence::default(),
            &mut [0; 1023],
            &mut session,
            0
        )),
        Err(Status::PinUvAuthTokenRequired)
    );
}
#[test]
fn client_pin_policy_and_uncertain_retry_writes_fail_closed() {
    for pin in [
        b"123".as_slice(),
        b"\xff\xff\xff\xff".as_slice(),
        b"ab\0cd".as_slice(),
    ] {
        let mut store = storage::Storage::default();
        let master = key();
        let mut random = rng();
        let mut repo = Repository::new(&mut store, &master, &mut random);
        assert_eq!(
            set_pin(&mut repo, &mut pin_session::Session::default(), pin),
            Err(Status::PinPolicyViolation)
        );
        assert!(store.values.is_empty());
    }
    for after in [false, true] {
        let mut store = storage::Storage::default();
        let master = key();
        let mut random = rng();
        let mut session = pin_session::Session::default();
        {
            let mut repo = Repository::new(&mut store, &master, &mut random);
            set_pin(&mut repo, &mut session, b"1234").unwrap();
        }
        store.fail_before = !after;
        store.fail_after = after;
        {
            let mut repo = Repository::new(&mut store, &master, &mut random);
            assert_eq!(
                token(&mut repo, &mut session, b"1234", 0),
                Err(Status::Other)
            );
        }
        store.fail_before = false;
        store.fail_after = false;
        let mut repo = Repository::new(&mut store, &master, &mut random);
        assert_eq!(
            ready(session.load(&mut repo)).unwrap().unwrap()[24],
            if after { 7 } else { 8 }
        );
    }
}

#[test]
fn discoverable_reconstruction_replacement_deletion_and_legacy_compatibility() {
    let mut store = storage::Storage::default();
    let (legacy, public) = fixture(&mut store);
    let master = key();
    let mut random = rng();
    let rp = sha256(b"example.com");
    let mut repo = Repository::new(&mut store, &master, &mut random);
    let first = ready(repo.create_discoverable(
        "example.com",
        b"one",
        Some("Account"),
        Some("Display"),
        Some("Example"),
    ))
    .unwrap();
    let first_id = *first.id();
    let second = ready(repo.create_discoverable("example.com", b"two", None, None, None)).unwrap();
    let second_id = *second.id();
    drop(repo);
    let mut repo = Repository::new(&mut store, &master, &mut random);
    let found = ready(repo.discover(&rp)).unwrap();
    assert_eq!(found.len, 2);
    assert_eq!(found.ids[0], second_id);
    assert_eq!(found.ids[1], first_id);
    assert_eq!(
        ready(repo.read(&legacy, &rp))
            .unwrap()
            .unwrap()
            .public_key()
            .unwrap(),
        public
    );
    let replacement = ready(repo.create_discoverable(
        "example.com",
        b"one",
        Some("New"),
        Some("Display new"),
        None,
    ))
    .unwrap();
    assert_ne!(replacement.id(), &first_id);
    assert!(ready(repo.read(&first_id, &rp)).unwrap().is_none());
    assert_eq!(ready(repo.discover(&rp)).unwrap().len, 2);
    assert!(ready(repo.discover(&sha256(b"other.test"))).unwrap().len == 0);
    assert_eq!(ready(repo.delete(replacement.id(), &rp)), Ok(true));
    assert!(ready(repo.read(replacement.id(), &rp)).unwrap().is_none());
    assert_eq!(ready(repo.discover(&rp)).unwrap().len, 1);
}
#[test]
fn discoverable_directory_commit_faults_preserve_old_or_new_account() {
    let master = key();
    let rp = sha256(b"example.com");
    for step in 1..=3 {
        for after in [false, true] {
            let mut store = storage::Storage::default();
            let mut random = rng();
            let old = {
                let mut repo = Repository::new(&mut store, &master, &mut random);
                *ready(repo.create_discoverable("example.com", b"user", None, None, None))
                    .unwrap()
                    .id()
            };
            store.fail_at = Some(store.writes + step);
            store.fail_before = !after;
            store.fail_after = after;
            {
                let mut repo = Repository::new(&mut store, &master, &mut random);
                assert!(
                    ready(repo.create_discoverable(
                        "example.com",
                        b"user",
                        Some("New"),
                        None,
                        None
                    ))
                    .is_err()
                );
            }
            store.fail_before = false;
            store.fail_after = false;
            store.fail_at = None;
            let mut repo = Repository::new(&mut store, &master, &mut random);
            let found = ready(repo.discover(&rp)).unwrap();
            assert_eq!(found.len, 1);
            let current = ready(repo.read(&found.ids[0], &rp)).unwrap().unwrap();
            assert_eq!(current.user_id(), b"user");
            assert_eq!(
                ready(repo.read(&old, &rp)).unwrap().is_none(),
                step == 3 && after
            );
        }
    }
}
#[test]
fn discoverable_capacity_corruption_and_utf8_are_bounded() {
    let mut store = storage::Storage::default();
    let master = key();
    let mut random = rng();
    let rp = sha256(b"example.com");
    let mut repo = Repository::new(&mut store, &master, &mut random);
    let name = "🦀".repeat(30);
    let first =
        ready(repo.create_discoverable("example.com", &[0], Some(&name), None, None)).unwrap();
    assert_eq!(first.name().unwrap().len(), 64);
    let id = *first.id();
    for i in 1..storage::credentials::MAX_DISCOVERABLE {
        ready(repo.create_discoverable("example.com", &[i as u8], None, None, None)).unwrap();
    }
    assert!(matches!(
        ready(repo.create_discoverable("example.com", b"full", None, None, None)),
        Err(Error::Full)
    ));
    ready(repo.create_discoverable("example.com", &[0], Some("Replacement"), None, None)).unwrap();
    assert!(ready(repo.read(&id, &rp)).unwrap().is_none());
    drop(repo);
    let address = 0x0300_0000 | u32::from(rp[0]);
    store.values.get_mut(&address).unwrap()[20] ^= 1;
    let mut repo = Repository::new(&mut store, &master, &mut random);
    assert!(matches!(ready(repo.discover(&rp)), Err(Error::Integrity)));
}
fn discovery_call(
    repo: &mut Repository<'_, '_, '_, '_, ChaCha20Rng>,
    session: &mut pin_session::Session,
    now: u64,
    verified: bool,
) -> Vec<u8> {
    let hash = [9; 32];
    let tag = if verified {
        Some(doohickey_crypto::ctap::hmac_sha256(
            &token(repo, session, b"1234", now).unwrap(),
            &hash,
        ))
    } else {
        None
    };
    let request = Request::GetAssertion(credentials::GetAssertion {
        rp_id: "example.com",
        client_data_hash: &hash,
        allow_list: None,
        options: credentials::AssertionOptions::default(),
        auth: pin_uv::AuthParameters {
            protocol: tag.as_ref().map(|_| 2),
            parameter: tag.as_ref().map(|t| t.as_slice()),
        },
        hmac_secret: None,
    });
    let mut out = [0; 1023];
    let n = ready(authenticator::execute_with_session(
        repo,
        request,
        &mut Presence::default(),
        &mut out,
        session,
        now,
    ))
    .unwrap();
    out[..n].to_vec()
}
#[test]
fn discoverable_assertions_continuations_privacy_timeout_and_invalidation() {
    let mut store = storage::Storage::default();
    let master = key();
    let mut random = rng();
    let mut repo = Repository::new(&mut store, &master, &mut random);
    let mut session = pin_session::Session::default();
    for user in [b"first".as_slice(), b"second".as_slice()] {
        ready(repo.create_discoverable("example.com", user, Some("Name"), Some("Display"), None))
            .unwrap();
    }
    let response = discovery_call(&mut repo, &mut session, 0, false);
    let map = cbor::decode(&response).unwrap();
    assert_eq!(map.get_int(5).unwrap().unwrap().unsigned().unwrap(), 2);
    let user = map.get_int(4).unwrap().unwrap();
    assert_eq!(
        user.get_text("id").unwrap().unwrap().bytes().unwrap(),
        b"second"
    );
    assert!(user.get_text("name").unwrap().is_none());
    let mut presence = Presence::default();
    let mut out = [0; 1023];
    let n = ready(authenticator::execute_with_session(
        &mut repo,
        Request::GetNextAssertion,
        &mut presence,
        &mut out,
        &mut session,
        1,
    ))
    .unwrap();
    assert_eq!(presence.calls, 0);
    let map = cbor::decode(&out[..n]).unwrap();
    assert!(map.get_int(5).unwrap().is_none());
    assert_eq!(
        map.get_int(4)
            .unwrap()
            .unwrap()
            .get_text("id")
            .unwrap()
            .unwrap()
            .bytes()
            .unwrap(),
        b"first"
    );
    assert_eq!(
        ready(authenticator::execute_with_session(
            &mut repo,
            Request::GetNextAssertion,
            &mut presence,
            &mut out,
            &mut session,
            2
        )),
        Err(Status::NotAllowed)
    );
    discovery_call(&mut repo, &mut session, 0, false);
    assert_eq!(
        ready(authenticator::execute_with_session(
            &mut repo,
            Request::GetNextAssertion,
            &mut presence,
            &mut out,
            &mut session,
            30000
        )),
        Err(Status::NotAllowed)
    );
    discovery_call(&mut repo, &mut session, 0, false);
    session.invalidate();
    assert_eq!(
        ready(authenticator::execute_with_session(
            &mut repo,
            Request::GetNextAssertion,
            &mut presence,
            &mut out,
            &mut session,
            1
        )),
        Err(Status::NotAllowed)
    );
    discovery_call(&mut repo, &mut session, 0, false);
    ready(authenticator::execute_with_session(
        &mut repo,
        Request::GetInfo,
        &mut presence,
        &mut out,
        &mut session,
        1,
    ))
    .unwrap();
    assert_eq!(
        ready(authenticator::execute_with_session(
            &mut repo,
            Request::GetNextAssertion,
            &mut presence,
            &mut out,
            &mut session,
            2
        )),
        Err(Status::NotAllowed)
    );
    set_pin(&mut repo, &mut session, b"1234").unwrap();
    let response = discovery_call(&mut repo, &mut session, 0, true);
    let map = cbor::decode(&response).unwrap();
    assert_eq!(map.get_int(2).unwrap().unwrap().bytes().unwrap()[32], 5);
    assert_eq!(
        map.get_int(4)
            .unwrap()
            .unwrap()
            .get_text("name")
            .unwrap()
            .unwrap()
            .text()
            .unwrap(),
        "Name"
    );
    let n = ready(authenticator::execute_with_session(
        &mut repo,
        Request::GetNextAssertion,
        &mut presence,
        &mut out,
        &mut session,
        1,
    ))
    .unwrap();
    assert_eq!(
        cbor::decode(&out[..n])
            .unwrap()
            .get_int(4)
            .unwrap()
            .unwrap()
            .get_text("displayName")
            .unwrap()
            .unwrap()
            .text()
            .unwrap(),
        "Display"
    );
}
#[test]
fn rk_make_commits_discoverable_credential_and_info_advertises_it() {
    let mut store = storage::Storage::default();
    let mut request = make_wire();
    request[1] = 0xa5;
    request.extend(b"\x07\xa1\x62rk\xf5");
    let response = call(&mut store, &request, &mut Presence::default()).unwrap();
    let auth = cbor::decode(&response)
        .unwrap()
        .get_int(2)
        .unwrap()
        .unwrap()
        .bytes()
        .unwrap();
    let id = &auth[55..115];
    let master = key();
    let mut random = rng();
    let mut repo = Repository::new(&mut store, &master, &mut random);
    assert!(
        ready(repo.read(id, &sha256(b"example.com")))
            .unwrap()
            .unwrap()
            .discoverable()
    );
    let info = call(&mut store, &[4], &mut Presence::default()).unwrap();
    assert!(
        cbor::decode(&info)
            .unwrap()
            .get_int(4)
            .unwrap()
            .unwrap()
            .get_text("rk")
            .unwrap()
            .unwrap()
            .boolean()
            .unwrap()
    );
}
