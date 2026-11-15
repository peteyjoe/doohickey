//! Real sequential-storage map + real encrypted repository over NOR semantics.
//! Cut every programmed byte of mutations, discard RAM, then reopen the map.
#![allow(dead_code, unused_imports)]
#[path = "../../ctap/authenticator.rs"]
mod authenticator;
#[path = "../../ctap/mod.rs"]
mod ctap;
#[path = "../../ctap/pin_session.rs"]
mod pin_session;
use ctap::{Request, Result, Status, cbor, credentials, info, pin_uv};
#[path = "support/nor_credential_storage.rs"]
mod storage;
use doohickey_crypto::{ctap::sha256, secrets::MasterKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use storage::credentials::Repository;
use zeroize::Zeroizing;
fn ready<F: core::future::Future>(future: F) -> F::Output {
    let mut f = std::pin::pin!(future);
    let mut cx = core::task::Context::from_waker(std::task::Waker::noop());
    match f.as_mut().poll(&mut cx) {
        core::task::Poll::Ready(v) => v,
        _ => panic!("I/O unexpectedly pending"),
    }
}
#[test]
fn every_torn_counter_and_tombstone_write_reopens_as_the_old_or_committed_record() {
    let key = MasterKey::from_bytes(Zeroizing::new([7; 32]));
    let rp = sha256(b"example.com");
    let image = storage::Image::default();
    let mut store = storage::Storage::open(image.clone());
    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let mut repo = Repository::new(&mut store, &key, &mut rng);
    let credential = ready(repo.create(&rp, b"user")).unwrap();
    let id = *credential.id();
    let public = credential.public_key().unwrap();
    drop(repo);
    drop(store);
    let baseline = image.0.borrow().bytes.clone();
    for delete in [false, true] {
        // Determine the exact number of physical byte mutations of this action.
        image.0.borrow_mut().bytes.clone_from(&baseline);
        image.0.borrow_mut().mutations = 0;
        let mut store = storage::Storage::open(image.clone());
        let mut rng = ChaCha20Rng::from_seed([2; 32]);
        let mut repo = Repository::new(&mut store, &key, &mut rng);
        if delete {
            ready(repo.delete(&id, &rp)).unwrap();
        } else {
            let mut c = ready(repo.read(&id, &rp)).unwrap().unwrap();
            ready(repo.advance_counter(&mut c)).unwrap();
        }
        drop(repo);
        drop(store);
        let bytes = image.0.borrow().mutations;
        assert!(bytes > 200);
        for cut in 0..=bytes {
            {
                let mut m = image.0.borrow_mut();
                m.bytes.clone_from(&baseline);
                m.remaining = Some(cut);
            }
            let mut store = storage::Storage::open(image.clone());
            let mut rng = ChaCha20Rng::from_seed([3; 32]);
            let mut repo = Repository::new(&mut store, &key, &mut rng);
            let success = if delete {
                ready(repo.delete(&id, &rp)).is_ok()
            } else {
                let mut c = ready(repo.read(&id, &rp)).unwrap().unwrap();
                ready(repo.advance_counter(&mut c)).is_ok()
            };
            drop(repo);
            drop(store);
            image.0.borrow_mut().remaining = None;
            let mut store = storage::Storage::open(image.clone());
            let mut rng = ChaCha20Rng::from_seed([4; 32]);
            let mut repo = Repository::new(&mut store, &key, &mut rng);
            let loaded = ready(repo.read(&id, &rp)).unwrap();
            if let Some(c) = loaded {
                assert_eq!(c.public_key().unwrap(), public);
                assert!(c.counter() <= 1);
                if success {
                    assert!(!delete);
                    assert_eq!(c.counter(), 1);
                }
            } else {
                assert!(delete);
            }
        }
    }
}

#[test]
fn torn_last_pin_attempt_cannot_turn_into_an_unset_pin() {
    use doohickey_crypto::ctap::{PinUvKeyAgreement, PinUvProtocol};
    let key = MasterKey::from_bytes(Zeroizing::new([7; 32]));
    let image = storage::Image::default();
    let mut store = storage::Storage::open(image.clone());
    let mut random = ChaCha20Rng::from_seed([1; 32]);
    {
        let mut repo = Repository::new(&mut store, &key, &mut random);
        let mut state = [0; 26];
        state[..8].copy_from_slice(b"DOOHPIN1");
        state[8..24].copy_from_slice(&sha256(b"1234")[..16]);
        state[24] = 1;
        state[25] = 4;
        ready(repo.pin_store(0x0200_0001, b"DOOHPIN1")).unwrap();
        ready(repo.pin_store(0x0200_0000, &state)).unwrap();
    }
    drop(store);
    let baseline = image.0.borrow().bytes.clone();
    for cut in 0..130 {
        {
            let mut m = image.0.borrow_mut();
            m.bytes.clone_from(&baseline);
            m.remaining = Some(cut);
        }
        let mut store = storage::Storage::open(image.clone());
        let mut repo = Repository::new(&mut store, &key, &mut random);
        let mut session = pin_session::Session::default();
        let mut out = [0; 512];
        let n = ready(session.handle(
            &mut repo,
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
        let client = PinUvKeyAgreement::generate(&mut ChaCha20Rng::from_seed([2; 32]));
        let shared = client.agree(&point, PinUvProtocol::Two).unwrap();
        let peer = client.public_key();
        let mut encrypted = [0; 32];
        shared
            .encrypt(
                &mut ChaCha20Rng::from_seed([3; 32]),
                &[9; 16],
                &mut encrypted,
            )
            .unwrap();
        assert!(
            ready(session.handle(
                &mut repo,
                pin_uv::Request::GetTokenWithPermissions {
                    protocol: 2,
                    key_agreement: &peer,
                    pin_hash_enc: &encrypted,
                    permissions: pin_uv::Permissions::from_bits(3).unwrap(),
                    rp_id: Some("example.com")
                },
                0,
                &mut out
            ))
            .is_err()
        );
        drop(repo);
        drop(store);
        image.0.borrow_mut().remaining = None;
        let mut store = storage::Storage::open(image.clone());
        let mut repo = Repository::new(&mut store, &key, &mut random);
        let state = ready(pin_session::Session::default().load(&mut repo))
            .unwrap()
            .unwrap();
        assert!(state[24] <= 1);
    }
}
