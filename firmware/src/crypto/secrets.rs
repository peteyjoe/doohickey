//! Device-secret encryption, independent from CTAP's legacy CBC requirements.

use crate::Error;
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub const ENVELOPE_OVERHEAD: usize = 1 + 24 + 16;
pub const ENVELOPE_VERSION: u8 = 1;

/// Asynchronous so OTP and test flash-backed providers use the same interface.
/// No hardcoded key or generate-on-every-boot fallback is supplied here.
pub trait MasterKeyProvider {
    fn load_master_key(&mut self) -> impl core::future::Future<Output = Result<MasterKey, Error>>;
}

/// A persistent 256-bit root secret. No Debug or Clone; key bytes zero on drop.
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    /// The caller owns secure provisioning and persistence of these bytes.
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
    /// Explicit provisioning operation. Persist securely before encrypting data.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = Zeroizing::new([0; 32]);
        rng.fill_bytes(&mut bytes[..]);
        Self(bytes)
    }
    /// Export only to a secure provisioning mechanism, never logs or plain flash.
    pub fn provisioning_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct SecretBox(Zeroizing<[u8; 32]>);

impl SecretBox {
    /// Domain-separated encryption key; do not reuse the master for pairing.
    pub fn from_master_key(master: &MasterKey) -> Self {
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(b"DOOHICKEY root keys v1"), &master.0[..])
            .expand(b"DOOHICKEY stored secrets v1", &mut key[..])
            .expect("32-byte HKDF output is valid");
        Self(key)
    }

    /// Envelope: version[1] || random nonce[24] || ciphertext || tag[16].
    /// Context should bind the record key, type, and encoding version so records
    /// cannot be swapped. Authenticated encryption does not prevent rollback.
    pub fn seal(
        &self,
        rng: &mut impl CryptoRngCore,
        context: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let len = plaintext
            .len()
            .checked_add(ENVELOPE_OVERHEAD)
            .ok_or(Error::InvalidLength)?;
        if output.len() < len {
            return Err(Error::BufferTooSmall);
        }
        output[0] = ENVELOPE_VERSION;
        let mut nonce = [0; 24];
        if rng.try_fill_bytes(&mut nonce).is_err() {
            output[..len].zeroize();
            return Err(Error::EntropyUnavailable);
        }
        output[1..25].copy_from_slice(&nonce);
        output[25..len - 16].copy_from_slice(plaintext);
        let cipher = XChaCha20Poly1305::new((&*self.0).into());
        let tag = match cipher.encrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            context,
            &mut output[25..len - 16],
        ) {
            Ok(tag) => tag,
            Err(_) => {
                output[..len].zeroize();
                return Err(Error::Authentication);
            }
        };
        output[len - 16..len].copy_from_slice(&tag);
        Ok(len)
    }

    /// Returns plaintext only after authentication; clears output on tag failure.
    pub fn open(&self, context: &[u8], envelope: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        if envelope.len() < ENVELOPE_OVERHEAD || envelope[0] != ENVELOPE_VERSION {
            return Err(Error::InvalidLength);
        }
        let len = envelope.len() - ENVELOPE_OVERHEAD;
        if output.len() < len {
            return Err(Error::BufferTooSmall);
        }
        output[..len].copy_from_slice(&envelope[25..25 + len]);
        let cipher = XChaCha20Poly1305::new((&*self.0).into());
        if cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&envelope[1..25]),
                context,
                &mut output[..len],
                envelope[25 + len..].into(),
            )
            .is_err()
        {
            output[..len].zeroize();
            return Err(Error::Authentication);
        }
        Ok(len)
    }
}
