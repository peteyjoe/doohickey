//! Encrypted ES256 credentials with backward-compatible legacy records and
//! committed discoverable directories. Await each mutation through readback.
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
const CAPACITY: usize = 660;
pub const MAX_DISCOVERABLE: usize = 14;
const CATALOG_SIZE: usize = 25 + MAX_DISCOVERABLE * ID_SIZE;
const RESIDENT_MAGIC: &[u8; 8] = b"DOOHCR02";
const CATALOG_MAGIC: &[u8; 8] = b"DOOHRK01";
pub struct Discovery {
    pub ids: Zeroizing<[[u8; ID_SIZE]; MAX_DISCOVERABLE]>,
    pub len: usize,
}
impl Default for Discovery {
    fn default() -> Self {
        Self {
            ids: Zeroizing::new([[0; ID_SIZE]; MAX_DISCOVERABLE]),
            len: 0,
        }
    }
}
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
pub struct Credential(Zeroizing<[u8; CAPACITY]>);
impl Credential {
    pub fn discoverable(&self) -> bool {
        &self.0[..8] == RESIDENT_MAGIC
    }
    pub fn name(&self) -> Option<&str> {
        (self.0[202] != 0)
            .then(|| core::str::from_utf8(&self.0[203..203 + usize::from(self.0[202])]).unwrap())
    }
    pub fn display_name(&self) -> Option<&str> {
        (self.0[267] != 0)
            .then(|| core::str::from_utf8(&self.0[268..268 + usize::from(self.0[267])]).unwrap())
    }
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
    async fn catalog(
        &mut self,
        rp: &[u8; 32],
    ) -> Result<Option<Zeroizing<[u8; CATALOG_SIZE]>>, Error> {
        let mut bytes = Zeroizing::new([0; CATALOG_SIZE]);
        let n = EncryptedStorage::new(self.storage, self.key, self.rng)
            .read(
                0x0300_0000 | u32::from(rp[0]),
                RecordKind::Configuration,
                &mut bytes[..],
            )
            .await
            .map_err(map_error)?;
        let Some(n) = n else {
            return Ok(None);
        };
        let count = usize::from(bytes[24]);
        if n != CATALOG_SIZE
            || &bytes[..8] != CATALOG_MAGIC
            || count > MAX_DISCOVERABLE
            || bytes[25 + count * ID_SIZE..].iter().any(|b| *b != 0)
        {
            return Err(Error::Integrity);
        }
        for i in 0..count {
            let id = &bytes[25 + i * ID_SIZE..25 + (i + 1) * ID_SIZE];
            if &id[..8] != ID_MAGIC
                || id[11] != 1
                || (0..i).any(|j| &bytes[25 + j * ID_SIZE..25 + (j + 1) * ID_SIZE] == id)
            {
                return Err(Error::Integrity);
            }
        }
        Ok(Some(bytes))
    }
    async fn write_catalog(
        &mut self,
        rp: &[u8; 32],
        bytes: &mut [u8; CATALOG_SIZE],
    ) -> Result<(), Error> {
        self.rng
            .try_fill_bytes(&mut bytes[8..24])
            .map_err(|_| Error::Entropy)?;
        EncryptedStorage::new(self.storage, self.key, self.rng)
            .store(
                0x0300_0000 | u32::from(rp[0]),
                RecordKind::Configuration,
                bytes,
            )
            .await
            .map_err(map_error)?;
        let readback = self.catalog(rp).await?.ok_or(Error::Integrity)?;
        if !bool::from(readback[..].ct_eq(bytes)) {
            return Err(Error::Integrity);
        }
        Ok(())
    }
    /// Directory order is commit/creation order. Return RP matches newest first.
    pub async fn discover(&mut self, rp: &[u8; 32]) -> Result<Discovery, Error> {
        let mut result = Discovery::default();
        let Some(catalog) = self.catalog(rp).await? else {
            return Ok(result);
        };
        for i in (0..usize::from(catalog[24])).rev() {
            let id = &catalog[25 + i * ID_SIZE..25 + (i + 1) * ID_SIZE];
            let address = u32::from_le_bytes(id[8..12].try_into().unwrap());
            let record = self.load_at(address).await?.ok_or(Error::Integrity)?;
            if !record.discoverable()
                || record.0[8] != 2
                || record.rp_id_hash()[0] != rp[0]
                || record.id().as_slice() != id
            {
                return Err(Error::Integrity);
            }
            if bool::from(record.rp_id_hash().ct_eq(rp)) {
                result.ids[result.len].copy_from_slice(id);
                result.len += 1;
            }
        }
        Ok(result)
    }
    /// The directory is the commit point. New data is written first; replacing
    /// a user atomically removes its old ID from both discovery and allow lists.
    pub async fn create_discoverable(
        &mut self,
        rp: &str,
        user: &[u8],
        name: Option<&str>,
        display: Option<&str>,
        rp_name: Option<&str>,
    ) -> Result<Credential, Error> {
        if rp.is_empty() || rp.len() > 253 {
            return Err(Error::InvalidUser);
        }
        let hash = sha256_local(rp.as_bytes());
        let matches = self.discover(&hash).await?;
        let mut previous = None;
        for id in &matches.ids[..matches.len] {
            let record = self.read(id, &hash).await?.ok_or(Error::Integrity)?;
            if record.user_id() == user {
                previous = Some(*id);
                break;
            }
        }
        let mut catalog = self.catalog(&hash).await?.unwrap_or_else(|| {
            let mut bytes = Zeroizing::new([0; CATALOG_SIZE]);
            bytes[..8].copy_from_slice(CATALOG_MAGIC);
            bytes
        });
        let mut count = usize::from(catalog[24]);
        if let Some(id) = previous {
            let index = (0..count)
                .find(|i| catalog[25 + i * ID_SIZE..25 + (i + 1) * ID_SIZE] == id)
                .ok_or(Error::Integrity)?;
            catalog.copy_within(
                25 + (index + 1) * ID_SIZE..25 + count * ID_SIZE,
                25 + index * ID_SIZE,
            );
            count -= 1;
            catalog[25 + count * ID_SIZE..].zeroize();
        } else if count == MAX_DISCOVERABLE {
            return Err(Error::Full);
        }
        let mut record = self.create(&hash, user).await?;
        record.0[..8].copy_from_slice(RESIDENT_MAGIC);
        record.0[8] = 2;
        for (text, length, start) in [(name, 202, 203), (display, 267, 268), (rp_name, 587, 588)] {
            if let Some(text) = text {
                let mut len = text.len().min(64);
                while !text.is_char_boundary(len) {
                    len -= 1;
                }
                record.0[length] = len as u8;
                record.0[start..start + len].copy_from_slice(&text.as_bytes()[..len]);
            }
        }
        record.0[332..334].copy_from_slice(&(rp.len() as u16).to_le_bytes());
        record.0[334..334 + rp.len()].copy_from_slice(rp.as_bytes());
        self.persist(&record).await?;
        catalog[25 + count * ID_SIZE..25 + (count + 1) * ID_SIZE].copy_from_slice(record.id());
        catalog[24] = (count + 1) as u8;
        self.write_catalog(&hash, &mut catalog).await?;
        Ok(record)
    }
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
        let mut bytes = Zeroizing::new([0; CAPACITY]);
        let Some(n) = EncryptedStorage::new(self.storage, self.key, self.rng)
            .read(address, RecordKind::Credential, &mut bytes[..])
            .await
            .map_err(map_error)?
        else {
            return Ok(None);
        };
        let resident = n == CAPACITY && &bytes[..8] == RESIDENT_MAGIC;
        if !(n == RECORD_SIZE && &bytes[..8] == RECORD_MAGIC || resident)
            || !matches!(bytes[8], 0..=2)
            || (bytes[8] == 2) != (resident && bytes[8] != 0)
            || self.address(&bytes[9..69], bytes[69..101].try_into().unwrap()) != Some(address)
        {
            return Err(Error::Integrity);
        }
        let record = Credential(bytes);
        if record.0[8] != 0 {
            if resident {
                for (length, start) in [(202, 203), (267, 268), (587, 588)] {
                    let len = usize::from(record.0[length]);
                    if len > 64
                        || core::str::from_utf8(&record.0[start..start + len]).is_err()
                        || record.0[start + len..start + 64].iter().any(|b| *b != 0)
                    {
                        return Err(Error::Integrity);
                    }
                }
                let len = u16::from_le_bytes(record.0[332..334].try_into().unwrap()) as usize;
                if len == 0
                    || len > 253
                    || core::str::from_utf8(&record.0[334..334 + len]).is_err()
                    || !bool::from(
                        sha256_local(&record.0[334..334 + len]).ct_eq(record.rp_id_hash()),
                    )
                    || record.0[334 + len..587].iter().any(|b| *b != 0)
                    || record.0[652..].iter().any(|b| *b != 0)
                {
                    return Err(Error::Integrity);
                }
            }
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
            .store(
                address,
                RecordKind::Credential,
                &credential.0[..if credential.discoverable() {
                    CAPACITY
                } else {
                    RECORD_SIZE
                }],
            )
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
        if record.discoverable() {
            let catalog = self.catalog(rp).await?.ok_or(Error::Integrity)?;
            if !catalog[25..25 + usize::from(catalog[24]) * ID_SIZE]
                .as_chunks::<ID_SIZE>()
                .0
                .iter()
                .any(|entry| entry == id)
            {
                return Ok(None);
            }
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
            let mut record = Credential(Zeroizing::new([0; CAPACITY]));
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
        if record.discoverable() && record.user_id() != user {
            return Err(Error::InvalidUser);
        }
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
        if record.discoverable() {
            let mut catalog = self.catalog(rp).await?.ok_or(Error::Integrity)?;
            let count = usize::from(catalog[24]);
            let position = (0..count)
                .find(|i| &catalog[25 + i * ID_SIZE..25 + (i + 1) * ID_SIZE] == id)
                .ok_or(Error::Integrity)?;
            catalog.copy_within(
                25 + (position + 1) * ID_SIZE..25 + count * ID_SIZE,
                25 + position * ID_SIZE,
            );
            catalog[25 + (count - 1) * ID_SIZE..].zeroize();
            catalog[24] -= 1;
            self.write_catalog(rp, &mut catalog).await?;
        }
        record.0[8] = 0;
        record.0[101..198].zeroize();
        self.persist(&record).await?;
        Ok(true)
    }
}

fn sha256_local(bytes: &[u8]) -> [u8; 32] {
    doohickey_crypto::ctap::sha256(bytes)
}
