#![allow(dead_code, unused_imports)]
#[path = "../../ctap/authenticator.rs"]
mod authenticator;
#[path = "../../ctap/mod.rs"]
mod ctap;
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
        (b"\x07\xa1\x62rk\xf5".as_slice(), Status::UnsupportedOption),
        (b"\x08\x40".as_slice(), Status::MissingParameter),
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
