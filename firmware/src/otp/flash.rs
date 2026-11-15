//! Test backend only. This file deliberately has no hardware OTP imports.
use super::record::{self, BootKeyHash, Error, RECORD_SIZE};
use crate::storage::Storage;
use doohickey_crypto::secrets::{MasterKey, MasterKeyProvider};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MASTER_KEY: u32 = 0xffff_ff00;
const BOOT_KEY: u32 = 0xffff_ff01;
const SEALED_KEY: u32 = 0xffff_ff02;
const SEALED: &[u8] = b"DOOHOTP1-sealed";

pub struct Otp<'s, 'd> {
    storage: &'s mut Storage<'d>,
}

impl<'s, 'd> Otp<'s, 'd> {
    /// Initialize Storage metadata before constructing this test adapter.
    /// Construction performs no reads/writes and never touches real OTP.
    pub fn new(storage: &'s mut Storage<'d>) -> Self {
        Self { storage }
    }

    async fn read_value(&mut self, key: u32) -> Result<Zeroizing<[u8; 32]>, Error> {
        let mut record = Zeroizing::new([0; RECORD_SIZE]);
        let n = self
            .storage
            .read_otp_test(key, &mut record[..])
            .await
            .map_err(|_| Error::Storage)?
            .ok_or(Error::Unprovisioned)?;
        record::decode(&record[..n])
    }
    async fn is_sealed(&mut self) -> Result<bool, Error> {
        let mut flag = [0; 32];
        match self
            .storage
            .read_otp_test(SEALED_KEY, &mut flag)
            .await
            .map_err(|_| Error::Storage)?
        {
            None => Ok(false),
            Some(n) if &flag[..n] == SEALED => Ok(true),
            Some(_) => Err(Error::Corrupt),
        }
    }
    async fn write_once(&mut self, key: u32, value: &[u8; 32]) -> Result<(), Error> {
        let record = record::encode(value)?;
        let mut old = Zeroizing::new([0; RECORD_SIZE]);
        if self
            .storage
            .read_otp_test(key, &mut old[..])
            .await
            .map_err(|_| Error::Storage)?
            .is_some()
        {
            return Err(Error::AlreadyProvisioned);
        }
        self.storage
            .store_otp_test(key, &record[..])
            .await
            .map_err(|_| Error::Storage)?;
        let recovered = self.read_value(key).await?;
        if !bool::from(recovered[..].ct_eq(value)) {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    pub async fn read_master_key(&mut self) -> Result<MasterKey, Error> {
        let key = self.read_value(MASTER_KEY).await?;
        if !self.is_sealed().await? {
            return Err(Error::NotSealed);
        }
        Ok(MasterKey::from_bytes(key))
    }
    pub async fn master_key_status(&mut self) -> Result<super::MasterStatus, Error> {
        match self.read_value(MASTER_KEY).await {
            Ok(_key) => Ok(if self.is_sealed().await? {
                super::MasterStatus::Sealed
            } else {
                super::MasterStatus::Unsealed
            }),
            Err(Error::Unprovisioned) if !self.is_sealed().await? => Ok(super::MasterStatus::Blank),
            Err(Error::Unprovisioned) => Err(Error::Corrupt),
            Err(error) => Err(error),
        }
    }
    pub async fn provision_master_key(&mut self, key: &MasterKey) -> Result<(), Error> {
        if self.is_sealed().await? {
            return Err(Error::AlreadyProvisioned);
        }
        self.write_once(MASTER_KEY, key.provisioning_bytes()).await
    }
    pub async fn seal_master_key(&mut self) -> Result<(), Error> {
        let _key = self.read_value(MASTER_KEY).await?;
        if self.is_sealed().await? {
            return Ok(());
        }
        self.storage
            .store_otp_test(SEALED_KEY, SEALED)
            .await
            .map_err(|_| Error::Storage)?;
        if !self.is_sealed().await? {
            return Err(Error::WriteFailed);
        }
        Ok(())
    }
    pub async fn read_secure_boot_key_hash(&mut self) -> Result<BootKeyHash, Error> {
        BootKeyHash::from_bytes(*self.read_value(BOOT_KEY).await?)
    }
    pub async fn provision_secure_boot_key_hash(
        &mut self,
        hash: &BootKeyHash,
    ) -> Result<(), Error> {
        self.write_once(BOOT_KEY, hash.as_bytes()).await
    }
}

impl MasterKeyProvider for Otp<'_, '_> {
    async fn load_master_key(&mut self) -> Result<MasterKey, doohickey_crypto::Error> {
        self.read_master_key()
            .await
            .map_err(|_| doohickey_crypto::Error::KeyUnavailable)
    }
}
