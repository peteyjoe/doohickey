//! Test the actual OTP policy and flash adapter using in-memory hardware/storage.
//! No hardware OTP accesses or fuse writes occur in these tests.
#[path = "../../otp/flash.rs"]
mod flash;
#[path = "../../otp/hardware_policy.rs"]
mod hardware_policy;
#[allow(dead_code)]
#[path = "../../otp/record.rs"]
mod record;

use doohickey_crypto::secrets::{MasterKey, MasterKeyProvider};
use hardware_policy::*;
use record::*;
use zeroize::Zeroizing;

fn ready<F: core::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = core::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        core::task::Poll::Ready(value) => value,
        core::task::Poll::Pending => panic!("mock I/O must complete immediately"),
    }
}

struct MockRows {
    raw: [u32; 4096],
    ecc: [u16; 4096],
    writes: usize,
    fail_after: Option<usize>,
}
impl MockRows {
    fn new() -> Self {
        Self {
            raw: [0; 4096],
            ecc: [0; 4096],
            writes: 0,
            fail_after: None,
        }
    }
    fn write_allowed(&mut self) -> Result<(), Error> {
        if self.fail_after == Some(self.writes) {
            return Err(Error::WriteFailed);
        }
        self.writes += 1;
        Ok(())
    }
}
impl Rows for MockRows {
    fn raw(&mut self, row: usize) -> Result<u32, Error> {
        Ok(self.raw[row])
    }
    fn ecc(&mut self, row: usize) -> Result<u16, Error> {
        Ok(self.ecc[row])
    }
    fn write_ecc(&mut self, row: usize, value: u16) -> Result<(), Error> {
        self.write_allowed()?;
        assert!(
            (MASTER_ROW..MASTER_ROW + RECORD_SIZE / 2).contains(&row)
                || (BOOT_HASH_ROW..BOOT_HASH_ROW + 16).contains(&row)
        );
        assert_eq!(self.raw[row], 0);
        // Model the data interface separately from ECC encoding. A data word
        // of zero is legitimate and must not be confused with a missing record.
        self.ecc[row] = value;
        self.raw[row] = u32::from(value);
        Ok(())
    }
    fn write_raw(&mut self, row: usize, value: u32) -> Result<(), Error> {
        self.write_allowed()?;
        assert_eq!(row, MASTER_LOCK1);
        assert_eq!(value, SEALED_LOCK);
        self.raw[row] |= value;
        Ok(())
    }
}

#[test]
fn hardware_master_is_write_once_and_must_be_sealed() {
    let mut rows = MockRows::new();
    assert_eq!(master_status(&mut rows), Ok(MasterStatus::Blank));
    assert!(matches!(read_master(&mut rows), Err(Error::Unprovisioned)));
    let mut key = [7; 32];
    key[..4].fill(0);
    provision_master(&mut rows, &key).unwrap();
    assert_eq!(master_status(&mut rows), Ok(MasterStatus::Unsealed));
    assert!(matches!(read_master(&mut rows), Err(Error::NotSealed)));
    assert_eq!(
        provision_master(&mut rows, &[8; 32]),
        Err(Error::AlreadyProvisioned)
    );
    seal_master(&mut rows).unwrap();
    assert_eq!(master_status(&mut rows), Ok(MasterStatus::Sealed));
    let recovered = read_master(&mut rows).unwrap();
    assert_eq!(*recovered, key);
    assert_eq!(rows.raw[MASTER_LOCK1], SEALED_LOCK);
    let writes = rows.writes;
    seal_master(&mut rows).unwrap();
    assert_eq!(rows.writes, writes);
    assert!(provision_master(&mut rows, &[8; 32]).is_err());
}

#[test]
fn interrupted_hardware_provisioning_never_loads_or_overwrites_partial_key() {
    for fail_after in 1..RECORD_SIZE / 2 {
        let mut rows = MockRows::new();
        rows.fail_after = Some(fail_after);
        assert_eq!(
            provision_master(&mut rows, &[7; 32]),
            Err(Error::WriteFailed)
        );
        rows.fail_after = None;
        assert!(master_status(&mut rows).is_err());
        assert!(read_master(&mut rows).is_err());
        assert!(seal_master(&mut rows).is_err());
        assert_eq!(
            provision_master(&mut rows, &[8; 32]),
            Err(Error::AlreadyProvisioned)
        );
    }
}

#[test]
fn corrupted_or_partially_locked_master_fails_closed() {
    let mut rows = MockRows::new();
    provision_master(&mut rows, &[7; 32]).unwrap();
    rows.raw[MASTER_LOCK1] = 0x0c;
    assert!(master_status(&mut rows).is_err());
    assert!(matches!(read_master(&mut rows), Err(Error::NotSealed)));
    assert_eq!(seal_master(&mut rows), Err(Error::PermissionDenied));
    rows.raw[MASTER_LOCK1] = SEALED_LOCK;
    rows.ecc[MASTER_ROW + 4] ^= 1;
    assert!(master_status(&mut rows).is_err());
    assert!(matches!(read_master(&mut rows), Err(Error::Corrupt)));
}

#[test]
fn boot_hash_uses_rom_slot_and_does_not_activate_secure_boot() {
    let mut rows = MockRows::new();
    let value = core::array::from_fn(|i| i as u8);
    let hash = BootKeyHash::from_bytes(value).unwrap();
    provision_boot_hash(&mut rows, &hash).unwrap();
    assert_eq!(read_boot_hash(&mut rows).unwrap(), hash);
    assert_eq!(rows.ecc[BOOT_HASH_ROW], 0x0100);
    assert!(rows.raw[..BOOT_HASH_ROW].iter().all(|word| *word == 0));
    assert_eq!(
        provision_boot_hash(&mut rows, &hash),
        Err(Error::AlreadyProvisioned)
    );
    for flag in [1, 0x100] {
        let mut rows = MockRows::new();
        rows.raw[0x4b] = flag;
        rows.raw[0x4c] = flag;
        assert_eq!(
            provision_boot_hash(&mut rows, &hash),
            Err(Error::AlreadyProvisioned)
        );
    }
}

#[test]
fn refuses_page_collisions_and_blank_values_without_writes() {
    let mut rows = MockRows::new();
    for key in [[0; 32], [0xff; 32]] {
        assert_eq!(provision_master(&mut rows, &key), Err(Error::InvalidValue));
        assert_eq!(rows.writes, 0);
    }
    rows.raw[MASTER_ROW + 63] = 1;
    assert_eq!(
        provision_master(&mut rows, &[7; 32]),
        Err(Error::AlreadyProvisioned)
    );
    assert_eq!(rows.writes, 0);
}

#[test]
fn metadata_record_detects_every_tampered_byte_and_truncation() {
    let valid = record::encode(&[7; 32]).unwrap();
    for i in 0..RECORD_SIZE {
        let mut changed = *valid;
        changed[i] ^= 1;
        assert!(record::decode(&changed).is_err());
        assert!(record::decode(&valid[..i]).is_err());
    }
}

// This test double models the reserved Storage API used by the real flash
// adapter. Normal metadata validation and hardware flash are tested separately.
mod storage {
    pub struct Storage<'d> {
        pub values: std::collections::BTreeMap<u32, std::vec::Vec<u8>>,
        pub fail: bool,
        pub _lifetime: core::marker::PhantomData<&'d ()>,
    }
    impl Storage<'_> {
        pub fn new() -> Self {
            Self {
                values: Default::default(),
                fail: false,
                _lifetime: core::marker::PhantomData,
            }
        }
        pub async fn read_otp_test(
            &mut self,
            key: u32,
            out: &mut [u8],
        ) -> Result<Option<usize>, ()> {
            if self.fail {
                return Err(());
            }
            match self.values.get(&key) {
                Some(value) if value.len() <= out.len() => {
                    out[..value.len()].copy_from_slice(value);
                    Ok(Some(value.len()))
                }
                Some(_) => Err(()),
                None => Ok(None),
            }
        }
        pub async fn store_otp_test(&mut self, key: u32, value: &[u8]) -> Result<(), ()> {
            if self.fail {
                return Err(());
            }
            self.values.insert(key, value.to_vec());
            Ok(())
        }
    }
}

#[test]
fn flash_adapter_persists_and_rejects_overwrites_with_same_public_api() {
    let mut storage = storage::Storage::new();
    let master = MasterKey::from_bytes(Zeroizing::new([7; 32]));
    let hash = BootKeyHash::from_bytes([8; 32]).unwrap();
    {
        let mut otp = flash::Otp::new(&mut storage);
        assert_eq!(ready(otp.master_key_status()), Ok(MasterStatus::Blank));
        assert!(matches!(
            ready(otp.read_master_key()),
            Err(Error::Unprovisioned)
        ));
        ready(otp.provision_master_key(&master)).unwrap();
        assert_eq!(ready(otp.master_key_status()), Ok(MasterStatus::Unsealed));
        assert!(matches!(
            ready(otp.read_master_key()),
            Err(Error::NotSealed)
        ));
        assert_eq!(
            ready(otp.provision_master_key(&master)),
            Err(Error::AlreadyProvisioned)
        );
        ready(otp.seal_master_key()).unwrap();
        assert_eq!(ready(otp.master_key_status()), Ok(MasterStatus::Sealed));
        ready(otp.provision_secure_boot_key_hash(&hash)).unwrap();
    }
    let mut otp = flash::Otp::new(&mut storage);
    assert_eq!(
        ready(otp.load_master_key()).unwrap().provisioning_bytes(),
        master.provisioning_bytes()
    );
    assert_eq!(ready(otp.read_secure_boot_key_hash()).unwrap(), hash);
    assert_eq!(
        ready(otp.provision_secure_boot_key_hash(&hash)),
        Err(Error::AlreadyProvisioned)
    );
    assert_eq!(
        ready(otp.provision_master_key(&master)),
        Err(Error::AlreadyProvisioned)
    );
}

#[test]
fn flash_adapter_propagates_failure_and_never_regenerates_keys() {
    let mut storage = storage::Storage::new();
    let master = MasterKey::from_bytes(Zeroizing::new([7; 32]));
    storage.fail = true;
    {
        let mut otp = flash::Otp::new(&mut storage);
        assert_eq!(
            ready(otp.provision_master_key(&master)),
            Err(Error::Storage)
        );
        assert!(matches!(
            ready(otp.load_master_key()),
            Err(doohickey_crypto::Error::KeyUnavailable)
        ));
    }
    storage.fail = false;
    assert!(storage.values.is_empty());
    {
        let mut otp = flash::Otp::new(&mut storage);
        ready(otp.provision_master_key(&master)).unwrap();
    }
    storage.values.get_mut(&0xffff_ff00).unwrap()[8] ^= 1;
    assert!(matches!(
        ready(flash::Otp::new(&mut storage).read_master_key()),
        Err(Error::Corrupt)
    ));
}

#[test]
fn locked_blank_or_corrupt_master_is_never_classified_as_provisionable() {
    for (row, lock) in [
        (MASTER_LOCK0, 1),
        (MASTER_LOCK1, 1),
        (MASTER_LOCK1, SEALED_LOCK),
    ] {
        let mut rows = MockRows::new();
        rows.raw[row] = lock;
        assert!(master_status(&mut rows).is_err());
        assert_eq!(rows.writes, 0);
    }
    let mut storage = storage::Storage::new();
    let master = MasterKey::from_bytes(Zeroizing::new([7; 32]));
    {
        let mut otp = flash::Otp::new(&mut storage);
        ready(otp.provision_master_key(&master)).unwrap();
        ready(otp.seal_master_key()).unwrap();
    }
    // A surviving seal flag with a missing emulated root is damage, not Blank.
    let root = storage.values.remove(&0xffff_ff00).unwrap();
    assert_eq!(
        ready(flash::Otp::new(&mut storage).master_key_status()),
        Err(Error::Corrupt)
    );
    storage.values.insert(0xffff_ff00, root);
    storage.values.get_mut(&0xffff_ff00).unwrap()[8] ^= 1;
    assert_eq!(
        ready(flash::Otp::new(&mut storage).master_key_status()),
        Err(Error::Corrupt)
    );
}
