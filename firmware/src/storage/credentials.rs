//! Encrypted, non-discoverable ES256 credential records. One key per record;
//! no directory/index transaction. Await each mutation through readback.
use super::{
    Storage,
    encrypted::{self, EncryptedStorage, RecordKind},
};
use doohickey_crypto::{
    ctap::{Es256Key, hmac_sha256},
    secrets::MasterKey,
};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const ID_SIZE: usize = 60;
pub const RECORD_SIZE: usize = 202;
pub const KEY_PREFIX: u32 = 0x0100_0000;
const RECORD_MAGIC: &[u8; 8] = b"DOOHCR01";
const ID_MAGIC: &[u8; 8] = b"DOOHCID1";
const ID_DOMAIN: &[u8] = b"DOOHICKEY credential id v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Io,
    Full,
    Integrity,
    Entropy,
    CounterExhausted,
    InvalidUser,
    NotFound,
}
fn map_error(error: encrypted::Error) -> Error {
    match error {
        encrypted::Error::Storage(error) if error.is_full() => Error::Full,
        encrypted::Error::Storage(_) => Error::Io,
        encrypted::Error::Crypto(doohickey_crypto::Error::EntropyUnavailable) => Error::Entropy,
        _ => Error::Integrity,
    }
}

/// Secret-bearing value: no Debug/Clone, including the retained user handle.
pub struct Credential(Zeroizing<[u8; RECORD_SIZE]>);
impl Credential {
    pub fn id(&self) -> &[u8; ID_SIZE] {
        self.0[9..69].try_into().unwrap()
    }
    pub fn rp_id_hash(&self) -> &[u8; 32] {
        self.0[69..101].try_into().unwrap()
    }
    pub fn user_id(&self) -> &[u8] {
        &self.0[102..102 + usize::from(self.0[101])]
    }
    pub fn counter(&self) -> u32 {
        u32::from_le_bytes(self.0[198..202].try_into().unwrap())
    }
    fn key(&self) -> Result<Es256Key, Error> {
        Es256Key::from_bytes(self.0[166..198].try_into().unwrap()).map_err(|_| Error::Integrity)
    }
    pub fn public_key(&self) -> Result<[u8; 65], Error> {
        Ok(self.key()?.public_key())
    }
    pub fn sign(&self, message: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        output.zeroize();
        self.key()?
            .sign(message, output)
            .map_err(|_| Error::Integrity)
    }
}

pub struct Repository<'s, 'd, 'k, 'r, R: CryptoRngCore> {
    storage: &'s mut Storage<'d>,
    key: &'k MasterKey,
    rng: &'r mut R,
    id_key: Zeroizing<[u8; 32]>,
}
impl<'s, 'd, 'k, 'r, R: CryptoRngCore> Repository<'s, 'd, 'k, 'r, R> {
    pub(crate) fn rng(&mut self) -> &mut R {
        self.rng
    }
    pub(crate) async fn pin_read(
        &mut self,
        key: u32,
        out: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        assert!(matches!(key, 0x0200_0000 | 0x0200_0001));
        EncryptedStorage::new(self.storage, self.key, self.rng)
            .read(key, RecordKind::Configuration, out)
            .await
            .map_err(map_error)
    }
    pub(crate) async fn pin_store(&mut self, key: u32, value: &[u8]) -> Result<(), Error> {
        assert!(matches!(key, 0x0200_0000 | 0x0200_0001));
        EncryptedStorage::new(self.storage, self.key, self.rng)
            .store(key, RecordKind::Configuration, value)
            .await
            .map_err(map_error)?;
        let mut check = Zeroizing::new([0; 64]);
        let n = self
            .pin_read(key, &mut check[..])
            .await?
            .ok_or(Error::Integrity)?;
        if !bool::from(check[..n].ct_eq(value)) {
            return Err(Error::Integrity);
        }
        Ok(())
    }
    /// Use the replaceable credential key from validated initialization, never
    /// the OTP root. Firmware versions and flash geometries are not KDF inputs.
    pub fn new(storage: &'s mut Storage<'d>, key: &'k MasterKey, rng: &'r mut R) -> Self {
        Self {
            storage,
            key,
            rng,
            id_key: Zeroizing::new(hmac_sha256(key.provisioning_bytes(), ID_DOMAIN)),
        }
    }
    fn tag(&self, prefix: &[u8], rp: &[u8; 32]) -> [u8; 32] {
        let mut input = [0; 60];
        input[..28].copy_from_slice(prefix);
        input[28..].copy_from_slice(rp);
        hmac_sha256(&self.id_key[..], &input)
    }
    fn address(&self, id: &[u8], rp: &[u8; 32]) -> Option<u32> {
        if id.len() != ID_SIZE || &id[..8] != ID_MAGIC {
            return None;
        }
        let address = u32::from_le_bytes(id[8..12].try_into().unwrap());
        if address & 0xff00_0000 != KEY_PREFIX
            || !bool::from(self.tag(&id[..28], rp).ct_eq(&id[28..]))
        {
            return None;
        }
        Some(address)
    }
    async fn load_at(&mut self, address: u32) -> Result<Option<Credential>, Error> {
        let mut bytes = Zeroizing::new([0; RECORD_SIZE]);
        let Some(n) = EncryptedStorage::new(self.storage, self.key, self.rng)
            .read(address, RecordKind::Credential, &mut bytes[..])
            .await
            .map_err(map_error)?
        else {
            return Ok(None);
        };
        if n != RECORD_SIZE
            || &bytes[..8] != RECORD_MAGIC
            || bytes[8] > 1
            || self.address(&bytes[9..69], bytes[69..101].try_into().unwrap()) != Some(address)
        {
            return Err(Error::Integrity);
        }
        let record = Credential(bytes);
        if record.0[8] == 1 {
            if record.0[101] == 0
                || record.0[101] > 64
                || record.0[102 + usize::from(record.0[101])..166]
                    .iter()
                    .any(|b| *b != 0)
            {
                return Err(Error::Integrity);
            }
            record.key()?;
        } else if record.0[101..198].iter().any(|b| *b != 0) {
            return Err(Error::Integrity);
        }
        Ok(Some(record))
    }
    async fn persist(&mut self, credential: &Credential) -> Result<(), Error> {
        let address = self
            .address(credential.id(), credential.rp_id_hash())
            .ok_or(Error::Integrity)?;
        EncryptedStorage::new(self.storage, self.key, self.rng)
            .store(address, RecordKind::Credential, &credential.0[..])
            .await
            .map_err(map_error)?;
        let readback = self.load_at(address).await?.ok_or(Error::Integrity)?;
        if !bool::from(readback.0[..].ct_eq(&credential.0[..])) {
            return Err(Error::Integrity);
        }
        Ok(())
    }
    /// Invalid/foreign IDs do not cause I/O. A valid owned ID whose record has
    /// disappeared is an integrity failure, not a new/empty credential store.
    pub async fn read(&mut self, id: &[u8], rp: &[u8; 32]) -> Result<Option<Credential>, Error> {
        let Some(address) = self.address(id, rp) else {
            return Ok(None);
        };
        let record = self.load_at(address).await?.ok_or(Error::Integrity)?;
        if !bool::from(record.id().ct_eq(id)) {
            return Err(Error::Integrity);
        }
        if record.0[8] == 0 {
            return Ok(None);
        }
        Ok(Some(record))
    }
    pub async fn create(&mut self, rp: &[u8; 32], user: &[u8]) -> Result<Credential, Error> {
        if user.is_empty() || user.len() > 64 {
            return Err(Error::InvalidUser);
        }
        let mut private = Zeroizing::new([0; 32]);
        let mut valid = false;
        for _ in 0..8 {
            self.rng
                .try_fill_bytes(&mut private[..])
                .map_err(|_| Error::Entropy)?;
            if Es256Key::from_bytes(&private).is_ok() {
                valid = true;
                break;
            }
        }
        if !valid {
            return Err(Error::Entropy);
        }
        for _ in 0..16 {
            let mut random = [0; 20];
            self.rng
                .try_fill_bytes(&mut random)
                .map_err(|_| Error::Entropy)?;
            let address =
                KEY_PREFIX | (u32::from_le_bytes(random[..4].try_into().unwrap()) & 0x00ff_ffff);
            // Tombstones are deliberately never reused. An interrupted create
            // can leave an unpublished record, but cannot destroy another ID.
            if self.load_at(address).await?.is_some() {
                continue;
            }
            let mut record = Credential(Zeroizing::new([0; RECORD_SIZE]));
            record.0[..8].copy_from_slice(RECORD_MAGIC);
            record.0[8] = 1;
            record.0[9..17].copy_from_slice(ID_MAGIC);
            record.0[17..21].copy_from_slice(&address.to_le_bytes());
            record.0[21..37].copy_from_slice(&random[4..]);
            let tag = self.tag(&record.0[9..37], rp);
            record.0[37..69].copy_from_slice(&tag);
            record.0[69..101].copy_from_slice(rp);
            record.0[101] = user.len() as u8;
            record.0[102..102 + user.len()].copy_from_slice(user);
            record.0[166..198].copy_from_slice(&private[..]);
            self.persist(&record).await?;
            return Ok(record);
        }
        Err(Error::Full)
    }
    /// Persist the complete record with its next per-credential counter BEFORE
    /// exposing a signature. A lost acknowledgement may skip a count, never
    /// knowingly reuse it. Reboot/reload is safe after an uncertain write.
    pub async fn advance_counter(&mut self, credential: &mut Credential) -> Result<u32, Error> {
        let mut current = self
            .read(credential.id(), credential.rp_id_hash())
            .await?
            .ok_or(Error::NotFound)?;
        if !bool::from(current.0[..].ct_eq(&credential.0[..])) {
            return Err(Error::Integrity);
        }
        let counter = current
            .counter()
            .checked_add(1)
            .ok_or(Error::CounterExhausted)?;
        current.0[198..202].copy_from_slice(&counter.to_le_bytes());
        self.persist(&current).await?;
        *credential = current;
        Ok(counter)
    }
    /// Replace only the user handle; ID, signing key and counter are retained.
    pub async fn update_user(
        &mut self,
        id: &[u8],
        rp: &[u8; 32],
        user: &[u8],
    ) -> Result<(), Error> {
        if user.is_empty() || user.len() > 64 {
            return Err(Error::InvalidUser);
        }
        let mut record = self.read(id, rp).await?.ok_or(Error::NotFound)?;
        record.0[101..166].zeroize();
        record.0[101] = user.len() as u8;
        record.0[102..102 + user.len()].copy_from_slice(user);
        self.persist(&record).await
    }
    /// Logical deletion leaves an authenticated tombstone. Historical encrypted
    /// flash entries remain; neither secure deletion nor rollback protection.
    pub async fn delete(&mut self, id: &[u8], rp: &[u8; 32]) -> Result<bool, Error> {
        let Some(mut record) = self.read(id, rp).await? else {
            return Ok(false);
        };
        record.0[8] = 0;
        record.0[101..198].zeroize();
        self.persist(&record).await?;
        Ok(true)
    }
}
