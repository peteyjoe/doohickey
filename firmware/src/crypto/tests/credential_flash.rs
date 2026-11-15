//! Real sequential-storage map + real encrypted repository over NOR semantics.
//! Cut every programmed byte of mutations, discard RAM, then reopen the map.
#![allow(dead_code)]
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
