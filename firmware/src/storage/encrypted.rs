//! Heap-free authenticated encryption over the regular byte-value store.
//!
//! Initialize Storage metadata and load the persistent master from OTP first.
//! Supply a CSPRNG seeded from HardwareEntropy; no entropy or key fallback is
//! provided here. Await operations to completion, as required by Storage.
//!
//! This wrapper does not migrate plaintext records, prevent rollback, provide
//! multi-key transactions, or authorize credential export. Application-owned
//! plaintext buffers must be zeroized by their owners when no longer needed.

use crate::storage::{self, MAX_VALUE_SIZE, Storage};
use doohickey_crypto::secrets::{ENVELOPE_OVERHEAD, MasterKey, SecretBox};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, Zeroizing};

/// One encrypted value still occupies a single Storage key.
pub const MAX_PLAINTEXT_SIZE: usize = MAX_VALUE_SIZE - ENVELOPE_OVERHEAD;

/// Stable v1 wrapper encoding, independent of the firmware package version.
/// Application payloads must also use an explicitly versioned serialization.
pub const ENCODING_VERSION: u8 = 1;

// These numeric values and the AAD layout are part of the persistent format.
// Never reassign them. Add a new kind for a different logical record type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    Credential = 1,
    PairingKey = 2,
    Configuration = 3,
}

#[derive(Debug)]
pub enum Error {
    /// The value cannot fit in a single encrypted record; no write occurred.
    ValueTooLarge,
    /// The record authenticated, but output is too small. Output is cleared.
    BufferTooSmall {
        required: usize,
    },
    Storage(storage::Error),
    /// Wrong key/kind/address, tampering, or an invalid/unsupported envelope.
    Crypto(doohickey_crypto::Error),
}

impl From<storage::Error> for Error {
    fn from(error: storage::Error) -> Self {
        Self::Storage(error)
    }
}

impl From<doohickey_crypto::Error> for Error {
    fn from(error: doohickey_crypto::Error) -> Self {
        Self::Crypto(error)
    }
}

/// Borrows one store and RNG; retains only a derived, zeroizing encryption key.
/// Construction performs no I/O and does not retain a reference to the master.
pub struct EncryptedStorage<'s, 'd, 'r, R: CryptoRngCore> {
    storage: &'s mut Storage<'d>,
    cipher: SecretBox,
    rng: &'r mut R,
}

impl<'s, 'd, 'r, R: CryptoRngCore> EncryptedStorage<'s, 'd, 'r, R> {
    pub fn new(storage: &'s mut Storage<'d>, master: &MasterKey, rng: &'r mut R) -> Self {
        Self {
            storage,
            cipher: SecretBox::from_master_key(master),
            rng,
        }
    }

    /// Encrypt the whole value using a fresh random nonce, then persist it.
    /// Replaces the previous logical value. Metadata/OTP keys remain reserved.
    /// Caller-owned plaintext is borrowed unchanged and is not wiped here.
    pub async fn store(&mut self, key: u32, kind: RecordKind, value: &[u8]) -> Result<(), Error> {
        if value.len() > MAX_PLAINTEXT_SIZE {
            return Err(Error::ValueTooLarge);
        }
        let mut envelope = Zeroizing::new([0; MAX_VALUE_SIZE]);
        let len = self
            .cipher
            .seal(self.rng, &context(key, kind), value, &mut envelope[..])?;
        self.storage.store(key, &envelope[..len]).await?;
        Ok(())
    }

    /// Returns None only for an absent key; Some(0) is an authenticated empty
    /// value. No plaintext is copied out until the entire record authenticates.
    /// Output is cleared on entry, including on absence and every error path.
    /// This method uses about 2 KiB of zeroizing temporary buffers.
    pub async fn read(
        &mut self,
        key: u32,
        kind: RecordKind,
        output: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        output.zeroize();
        let mut envelope = Zeroizing::new([0; MAX_VALUE_SIZE]);
        let Some(len) = self.storage.read(key, &mut envelope[..]).await? else {
            return Ok(None);
        };
        let mut plaintext = Zeroizing::new([0; MAX_PLAINTEXT_SIZE]);
        let len = self
            .cipher
            .open(&context(key, kind), &envelope[..len], &mut plaintext[..])?;
        if output.len() < len {
            return Err(Error::BufferTooSmall { required: len });
        }
        output[..len].copy_from_slice(&plaintext[..len]);
        Ok(Some(len))
    }
}

const DOMAIN: &[u8; 27] = b"DOOHICKEY encrypted storage";
const CONTEXT_SIZE: usize = DOMAIN.len() + 1 + 1 + 4;

fn context(key: u32, kind: RecordKind) -> [u8; CONTEXT_SIZE] {
    // Fixed-width, unambiguous AAD: domain || encoding u8 || kind u8 || key LE32.
    // The AEAD envelope supplies its own version, nonce, ciphertext, and tag.
    let mut aad = [0; CONTEXT_SIZE];
    aad[..DOMAIN.len()].copy_from_slice(DOMAIN);
    aad[DOMAIN.len()] = ENCODING_VERSION;
    aad[DOMAIN.len() + 1] = kind as u8;
    aad[DOMAIN.len() + 2..].copy_from_slice(&key.to_le_bytes());
    aad
}
