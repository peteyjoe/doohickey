//! Exercise the actual firmware adapter with real crypto and an in-memory
//! substitute for Storage. These tests do not access hardware flash or OTP.
#[path = "../../storage/encrypted.rs"]
mod encrypted;

use doohickey_crypto::{
    Error as CryptoError,
    secrets::{MasterKey, SecretBox},
};
use encrypted::{EncryptedStorage, Error, MAX_PLAINTEXT_SIZE, RecordKind};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use zeroize::Zeroizing;

fn ready<F: core::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = core::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        core::task::Poll::Ready(value) => value,
        core::task::Poll::Pending => panic!("mock I/O must complete immediately"),
    }
}

fn master(byte: u8) -> MasterKey {
    MasterKey::from_bytes(Zeroizing::new([byte; 32]))
}

mod storage {
    pub const MAX_VALUE_SIZE: usize = 1024;
    #[derive(Debug, PartialEq, Eq)]
    pub enum Error {
        ReservedKey,
        ValueTooLarge,
        BufferTooSmall,
        ReadFailed,
        WriteFailed,
    }

    #[derive(Default)]
    pub struct Storage<'d> {
        pub values: std::collections::BTreeMap<u32, Vec<u8>>,
        pub fail_read: bool,
        pub fail_write: bool,
        pub pending_read: bool,
        pub reads: usize,
        pub writes: usize,
        pub _lifetime: core::marker::PhantomData<&'d ()>,
    }

    fn check_key(key: u32) -> Result<(), Error> {
        if key == 0 || (0xffff_ff00..=0xffff_ff02).contains(&key) {
            Err(Error::ReservedKey)
        } else {
            Ok(())
        }
    }

    impl Storage<'_> {
        pub async fn read(&mut self, key: u32, out: &mut [u8]) -> Result<Option<usize>, Error> {
            self.reads += 1;
            check_key(key)?;
            if self.pending_read {
                core::future::pending::<()>().await;
            }
            if self.fail_read {
                return Err(Error::ReadFailed);
            }
            let Some(value) = self.values.get(&key) else {
                return Ok(None);
            };
            if value.len() > out.len() {
                return Err(Error::BufferTooSmall);
            }
            out[..value.len()].copy_from_slice(value);
            Ok(Some(value.len()))
        }

        pub async fn store(&mut self, key: u32, value: &[u8]) -> Result<(), Error> {
            self.writes += 1;
            check_key(key)?;
            if self.fail_write {
                return Err(Error::WriteFailed);
            }
            if value.len() > MAX_VALUE_SIZE {
                return Err(Error::ValueTooLarge);
            }
            self.values.insert(key, value.to_vec());
            Ok(())
        }
    }
}

#[test]
fn persists_across_handles_and_raw_store_contains_only_an_envelope() {
    let mut storage = storage::Storage::default();
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let key = master(7);
    let plaintext = b"private credential material";
    {
        let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
        ready(secrets.store(42, RecordKind::Credential, plaintext)).unwrap();
    }
    let raw = &storage.values[&42];
    assert_eq!(raw.len(), plaintext.len() + 41);
    assert!(
        !raw.windows(plaintext.len())
            .any(|window| window == plaintext)
    );
    let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
    let mut output = [0xa5; 64];
    assert_eq!(
        ready(secrets.read(42, RecordKind::Credential, &mut output)).unwrap(),
        Some(plaintext.len())
    );
    assert_eq!(&output[..plaintext.len()], plaintext);
    assert!(output[plaintext.len()..].iter().all(|byte| *byte == 0));
}

#[test]
fn overwrites_use_fresh_nonces_and_leave_caller_plaintext_unchanged() {
    let mut storage = storage::Storage::default();
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let key = master(7);
    let plaintext = [0xab; 32];
    {
        let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
        ready(secrets.store(42, RecordKind::Credential, &plaintext)).unwrap();
    }
    let first = storage.values[&42].clone();
    {
        let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
        ready(secrets.store(42, RecordKind::Credential, &plaintext)).unwrap();
    }
    assert_ne!(&first[1..25], &storage.values[&42][1..25]);
    assert_ne!(first, storage.values[&42]);
    assert_eq!(plaintext, [0xab; 32]);
}

#[test]
fn distinguishes_missing_from_authenticated_empty_values() {
    let mut storage = storage::Storage::default();
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let key = master(7);
    let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
    let mut output = [0xa5; 16];
    assert_eq!(
        ready(secrets.read(42, RecordKind::Credential, &mut output)).unwrap(),
        None
    );
    assert_eq!(output, [0; 16]);
    ready(secrets.store(42, RecordKind::Credential, b"")).unwrap();
    output.fill(0xa5);
    assert_eq!(
        ready(secrets.read(42, RecordKind::Credential, &mut output)).unwrap(),
        Some(0)
    );
    assert_eq!(output, [0; 16]);
    assert_eq!(
        ready(secrets.read(42, RecordKind::Credential, &mut [])).unwrap(),
        Some(0)
    );
}

#[test]
fn maximum_size_fits_and_oversized_values_never_touch_storage() {
    let mut storage = storage::Storage::default();
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let key = master(7);
    let plaintext = [0xab; 983];
    assert_eq!(MAX_PLAINTEXT_SIZE, plaintext.len());
    {
        let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
        ready(secrets.store(42, RecordKind::Credential, &plaintext)).unwrap();
        let mut output = [0; 983];
        assert_eq!(
            ready(secrets.read(42, RecordKind::Credential, &mut output)).unwrap(),
            Some(983)
        );
        assert_eq!(output, plaintext);
        assert!(matches!(
            ready(secrets.store(42, RecordKind::Credential, &[0; 984])),
            Err(Error::ValueTooLarge)
        ));
    }
    assert_eq!(storage.values[&42].len(), 1024);
    assert_eq!(storage.writes, 1);
}

#[test]
fn small_buffers_are_cleared_and_can_be_retried() {
    let mut storage = storage::Storage::default();
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let key = master(7);
    let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
    ready(secrets.store(42, RecordKind::Credential, b"secret")).unwrap();
    let mut small = [0xa5; 5];
    assert!(matches!(
        ready(secrets.read(42, RecordKind::Credential, &mut small)),
        Err(Error::BufferTooSmall { required: 6 })
    ));
    assert_eq!(small, [0; 5]);
    let mut output = [0; 6];
    assert_eq!(
        ready(secrets.read(42, RecordKind::Credential, &mut output)).unwrap(),
        Some(6)
    );
    assert_eq!(&output, b"secret");
}

#[test]
fn rejects_other_keys_record_kinds_and_moved_records() {
    let mut storage = storage::Storage::default();
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let key = master(7);
    {
        let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
        ready(secrets.store(42, RecordKind::Credential, b"secret")).unwrap();
    }
    storage.values.insert(43, storage.values[&42].clone());
    let wrong_master = master(8);
    for (master, kind, address) in [
        (&wrong_master, RecordKind::Credential, 42),
        (&key, RecordKind::PairingKey, 42),
        (&key, RecordKind::Configuration, 42),
        (&key, RecordKind::Credential, 43),
    ] {
        let mut secrets = EncryptedStorage::new(&mut storage, master, &mut rng);
        let mut output = [0xa5; 16];
        assert!(matches!(
            ready(secrets.read(address, kind, &mut output)),
            Err(Error::Crypto(CryptoError::Authentication))
        ));
        assert_eq!(output, [0; 16]);
    }
}

#[test]
fn every_tampered_byte_and_truncated_envelope_fails_without_plaintext() {
    let mut storage = storage::Storage::default();
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let key = master(7);
    {
        let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
        ready(secrets.store(42, RecordKind::Credential, b"secret")).unwrap();
    }
    let original = storage.values[&42].clone();
    let mut malformed: Vec<Vec<u8>> = (0..original.len())
        .map(|len| original[..len].to_vec())
        .collect();
    for offset in 0..original.len() {
        let mut value = original.clone();
        value[offset] ^= 1;
        malformed.push(value);
    }
    malformed.push(b"legacy plaintext record".to_vec());
    for value in malformed {
        storage.values.insert(42, value);
        let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
        let mut output = [0xa5; 32];
        assert!(matches!(
            ready(secrets.read(42, RecordKind::Credential, &mut output)),
            Err(Error::Crypto(_))
        ));
        assert_eq!(output, [0; 32]);
        // Authenticate before trusting even the apparent plaintext length.
        assert!(matches!(
            ready(secrets.read(42, RecordKind::Credential, &mut [])),
            Err(Error::Crypto(_))
        ));
    }
}

#[test]
fn persistent_aad_format_is_pinned_and_different_encoding_versions_fail() {
    let mut storage = storage::Storage::default();
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let key = master(7);
    const ADDRESS: u32 = 0x01020304;
    {
        let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
        ready(secrets.store(ADDRESS, RecordKind::Credential, b"secret")).unwrap();
    }
    // Independent literal prevents unnoticed changes to domain/version/tag/
    // byte order from making existing records unreadable in a firmware update.
    let aad = b"DOOHICKEY encrypted storage\x01\x01\x04\x03\x02\x01";
    let cipher = SecretBox::from_master_key(&key);
    let mut output = [0; 6];
    assert_eq!(
        cipher
            .open(aad, &storage.values[&ADDRESS], &mut output)
            .unwrap(),
        6
    );
    assert_eq!(&output, b"secret");
    let mut other_version = *aad;
    other_version[27] = 2;
    let mut envelope = [0; 47];
    cipher
        .seal(&mut rng, &other_version, b"secret", &mut envelope)
        .unwrap();
    storage.values.insert(ADDRESS, envelope.to_vec());
    let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
    output.fill(0xa5);
    assert!(matches!(
        ready(secrets.read(ADDRESS, RecordKind::Credential, &mut output)),
        Err(Error::Crypto(CryptoError::Authentication))
    ));
    assert_eq!(output, [0; 6]);
}

#[test]
fn reserved_keys_and_underlying_io_errors_are_preserved() {
    let mut storage = storage::Storage::default();
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let key = master(7);
    {
        let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
        for address in [0, 0xffff_ff00, 0xffff_ff01, 0xffff_ff02] {
            let mut output = [0xa5; 16];
            assert!(matches!(
                ready(secrets.read(address, RecordKind::Credential, &mut output)),
                Err(Error::Storage(storage::Error::ReservedKey))
            ));
            assert_eq!(output, [0; 16]);
            assert!(matches!(
                ready(secrets.store(address, RecordKind::Credential, b"secret")),
                Err(Error::Storage(storage::Error::ReservedKey))
            ));
        }
    }
    assert!(storage.values.is_empty());
    storage.fail_write = true;
    {
        let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
        assert!(matches!(
            ready(secrets.store(42, RecordKind::Credential, b"secret")),
            Err(Error::Storage(storage::Error::WriteFailed))
        ));
    }
    assert!(storage.values.is_empty());
    storage.fail_read = true;
    let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
    let mut output = [0xa5; 16];
    assert!(matches!(
        ready(secrets.read(42, RecordKind::Credential, &mut output)),
        Err(Error::Storage(storage::Error::ReadFailed))
    ));
    assert_eq!(output, [0; 16]);
}

#[test]
fn output_is_cleared_before_waiting_for_io() {
    let mut storage = storage::Storage {
        pending_read: true,
        ..Default::default()
    };
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let key = master(7);
    let mut secrets = EncryptedStorage::new(&mut storage, &key, &mut rng);
    let mut output = [0xa5; 16];
    {
        let mut future = std::pin::pin!(secrets.read(42, RecordKind::Credential, &mut output));
        let mut context = core::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            future.as_mut().poll(&mut context),
            core::task::Poll::Pending
        ));
    }
    assert_eq!(output, [0; 16]);
}
