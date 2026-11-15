//! ES256 and CTAP PIN/UV auth protocols 1 and 2. COSE/CBOR, CTAP command
//! validation, permissions, retries, user presence, and token lifetime belong
//! in the authenticator layer. Only advertise algorithms actually implemented.

use crate::Error;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{
    PublicKey, SecretKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::sec1::ToEncodedPoint,
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub fn sha256(message: &[u8]) -> [u8; 32] {
    Sha256::digest(message).into()
}

/// Decoder-side validation of an uncompressed EC2/P-256 agreement public key.
/// COSE kty/curve/algorithm checks remain the protocol decoder's responsibility.
pub fn validate_key_agreement(point: &[u8; 65]) -> Result<(), Error> {
    if point[0] != 4 {
        return Err(Error::InvalidKey);
    }
    PublicKey::from_sec1_bytes(point)
        .map(|_| ())
        .map_err(|_| Error::InvalidKey)
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// P-256 credential key. Deliberately has no Debug/Clone implementation.
pub struct Es256Key(SigningKey);

impl Es256Key {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        Self(SigningKey::random(rng))
    }
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        SigningKey::from_bytes(bytes.into())
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }
    /// Explicit secret export for authenticated encryption before persistence.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes().into())
    }
    /// SEC1 uncompressed point: 0x04 || x[32] || y[32]. COSE uses x/y separately.
    pub fn public_key(&self) -> [u8; 65] {
        self.0
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .expect("P-256 point size")
    }
    /// SHA-256 hashes the message once and returns a DER-encoded ECDSA signature
    /// as used in WebAuthn. Pass authenticatorData || clientDataHash, not its hash.
    /// RustCrypto uses deterministic RFC6979 nonces, not caller-supplied nonces.
    pub fn sign(&self, message: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let signature: Signature = self.0.sign(message);
        let der = signature.to_der();
        if output.len() < der.as_bytes().len() {
            return Err(Error::BufferTooSmall);
        }
        output[..der.as_bytes().len()].copy_from_slice(der.as_bytes());
        Ok(der.as_bytes().len())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinUvProtocol {
    One,
    Two,
}

/// Ephemeral P-256 key agreement, separate from credential/attestation keys.
pub struct PinUvKeyAgreement(SecretKey);

impl PinUvKeyAgreement {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        Self(SecretKey::random(rng))
    }
    pub fn public_key(&self) -> [u8; 65] {
        self.0
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .expect("P-256 point size")
    }
    /// Peer must be an uncompressed P-256 point from a validated COSE key
    /// (kty=EC2, crv=P-256, alg=-25). Curve membership is checked here too.
    pub fn agree(
        &self,
        peer: &[u8; 65],
        protocol: PinUvProtocol,
    ) -> Result<PinUvSharedSecret, Error> {
        if peer[0] != 4 {
            return Err(Error::InvalidKey);
        }
        let peer = PublicKey::from_sec1_bytes(peer).map_err(|_| Error::InvalidKey)?;
        let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.as_affine());
        PinUvSharedSecret::derive(shared.raw_secret_bytes().as_slice(), protocol)
    }
}

pub struct PinUvSharedSecret {
    protocol: PinUvProtocol,
    aes: Zeroizing<[u8; 32]>,
    hmac: Zeroizing<[u8; 32]>,
}

impl PinUvSharedSecret {
    fn derive(z: &[u8], protocol: PinUvProtocol) -> Result<Self, Error> {
        let mut aes = Zeroizing::new([0; 32]);
        let mut hmac = Zeroizing::new([0; 32]);
        match protocol {
            PinUvProtocol::One => {
                aes.copy_from_slice(&sha256(z));
                hmac.copy_from_slice(&aes[..]);
            }
            PinUvProtocol::Two => {
                let kdf = Hkdf::<Sha256>::new(Some(&[0; 32]), z);
                kdf.expand(b"CTAP2 HMAC key", &mut hmac[..])
                    .map_err(|_| Error::InvalidLength)?;
                kdf.expand(b"CTAP2 AES key", &mut aes[..])
                    .map_err(|_| Error::InvalidLength)?;
            }
        }
        Ok(Self {
            protocol,
            aes,
            hmac,
        })
    }

    pub fn authentication_len(&self) -> usize {
        match self.protocol {
            PinUvProtocol::One => 16,
            PinUvProtocol::Two => 32,
        }
    }
    /// Authenticate the exact command-specific byte string required by CTAP.
    pub fn authenticate(&self, message: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let len = self.authentication_len();
        if output.len() < len {
            return Err(Error::BufferTooSmall);
        }
        let tag = Zeroizing::new(hmac_sha256(&self.hmac[..], message));
        output[..len].copy_from_slice(&tag[..len]);
        Ok(len)
    }
    pub fn verify_authentication(&self, message: &[u8], tag: &[u8]) -> Result<(), Error> {
        let len = self.authentication_len();
        if tag.len() != len {
            return Err(Error::Authentication);
        }
        let expected = Zeroizing::new(hmac_sha256(&self.hmac[..], message));
        if bool::from(expected[..len].ct_eq(tag)) {
            Ok(())
        } else {
            Err(Error::Authentication)
        }
    }

    /// CTAP-only CBC, without padding. Protocol 1 uses IV=0; protocol 2 prefixes
    /// a fresh random IV. This is NOT authenticated encryption for arbitrary data.
    pub fn encrypt(
        &self,
        rng: &mut impl CryptoRngCore,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Error> {
        if plaintext.is_empty() || !plaintext.len().is_multiple_of(16) {
            return Err(Error::InvalidLength);
        }
        let prefix = if self.protocol == PinUvProtocol::Two {
            16
        } else {
            0
        };
        let len = plaintext
            .len()
            .checked_add(prefix)
            .ok_or(Error::InvalidLength)?;
        if output.len() < len {
            return Err(Error::BufferTooSmall);
        }
        let mut iv = [0; 16];
        if prefix != 0 {
            rng.fill_bytes(&mut iv);
            output[..16].copy_from_slice(&iv);
        }
        cbc::Encryptor::<aes::Aes256>::new((&*self.aes).into(), (&iv).into())
            .encrypt_padded_b2b_mut::<NoPadding>(plaintext, &mut output[prefix..len])
            .map_err(|_| Error::InvalidLength)?;
        Ok(len)
    }

    /// Low-level CTAP CBC only: verify pinUvAuthParam over the required CTAP
    /// command bytes BEFORE calling this. Do not use for storage or serial data.
    /// Protocol rules additionally constrain plaintext lengths and semantics.
    pub fn decrypt(&self, ciphertext: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let prefix = if self.protocol == PinUvProtocol::Two {
            16
        } else {
            0
        };
        if ciphertext.len() <= prefix || !(ciphertext.len() - prefix).is_multiple_of(16) {
            return Err(Error::InvalidLength);
        }
        let len = ciphertext.len() - prefix;
        if output.len() < len {
            return Err(Error::BufferTooSmall);
        }
        let mut iv = [0; 16];
        if prefix != 0 {
            iv.copy_from_slice(&ciphertext[..16]);
        }
        let result = cbc::Decryptor::<aes::Aes256>::new((&*self.aes).into(), (&iv).into())
            .decrypt_padded_b2b_mut::<NoPadding>(&ciphertext[prefix..], &mut output[..len]);
        if result.is_err() {
            output[..len].zeroize();
            return Err(Error::InvalidLength);
        }
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn sha256_and_rfc4231_hmac_vectors() {
        assert_eq!(
            sha256(b"abc"),
            hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            hmac_sha256(&[0x0b; 20], b"Hi There"),
            hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }

    #[test]
    fn rfc5869_hkdf_vector() {
        let hkdf = Hkdf::<Sha256>::new(Some(&hex!("000102030405060708090a0b0c")), &[0x0b; 22]);
        let mut out = [0; 42];
        hkdf.expand(&hex!("f0f1f2f3f4f5f6f7f8f9"), &mut out)
            .unwrap();
        assert_eq!(
            out,
            hex!(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    #[test]
    fn protocol_kdf_labels_match_independent_python_hkdf() {
        let z = core::array::from_fn::<_, 32, _>(|i| i as u8);
        let one = PinUvSharedSecret::derive(&z, PinUvProtocol::One).unwrap();
        assert_eq!(
            *one.aes,
            hex!("630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd")
        );
        assert_eq!(*one.aes, *one.hmac);
        let two = PinUvSharedSecret::derive(&z, PinUvProtocol::Two).unwrap();
        // Independent Python stdlib HMAC/SHA-256, RFC5869 expand with L=32.
        assert_eq!(
            *two.aes,
            hex!("0f6ff2ef211829c11638ef2893ea02edf195658c0572393e7680d93bc2b58d44")
        );
        assert_eq!(
            *two.hmac,
            hex!("a689b3b92a6ebab91192408da9c4f05c674a2bc5f938d613077716c719a8df39")
        );
        assert_ne!(*two.aes, *two.hmac);
        assert_ne!(*one.aes, *two.aes);
    }

    #[test]
    fn nist_aes256_cbc_vector_and_iv_prefix() {
        struct IvRng(u8);
        impl rand_core::RngCore for IvRng {
            fn next_u32(&mut self) -> u32 {
                panic!("test uses fill_bytes")
            }
            fn next_u64(&mut self) -> u64 {
                panic!("test uses fill_bytes")
            }
            fn fill_bytes(&mut self, out: &mut [u8]) {
                for b in out {
                    *b = self.0;
                    self.0 += 1;
                }
            }
            fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(out);
                Ok(())
            }
        }
        impl rand_core::CryptoRng for IvRng {}
        let shared = PinUvSharedSecret {
            protocol: PinUvProtocol::Two,
            aes: Zeroizing::new(hex!(
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
            )),
            hmac: Zeroizing::new([0; 32]),
        };
        let plaintext = hex!("6bc1bee22e409f96e93d7e117393172a");
        let mut output = [0; 32];
        assert_eq!(
            shared.encrypt(&mut IvRng(0), &plaintext, &mut output),
            Ok(32)
        );
        assert_eq!(
            output,
            hex!("000102030405060708090a0b0c0d0e0ff58c4c04d6e5f1ba779eabfb5f7bfbd6")
        );
        let mut recovered = [0; 16];
        assert_eq!(shared.decrypt(&output, &mut recovered), Ok(16));
        assert_eq!(recovered, plaintext);
    }
}
