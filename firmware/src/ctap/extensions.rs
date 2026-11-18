//! Mandatory extensions for the selected profile. The hmac-secret helper uses
//! protocol 2 only; authorization and credential selection stay in the backend.

use super::{
    pin_uv::PROTOCOL_TWO,
    status::{Result, Status},
};
use doohickey_crypto::ctap::{PinUvKeyAgreement, PinUvProtocol, hmac_sha256};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum CredProtect {
    /// userVerificationOptional
    #[default]
    Optional = 1,
    /// userVerificationOptionalWithCredentialIDList
    OptionalWithCredentialIdList = 2,
    /// userVerificationRequired
    Required = 3,
}

impl TryFrom<u8> for CredProtect {
    type Error = Status;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Optional),
            2 => Ok(Self::OptionalWithCredentialIdList),
            3 => Ok(Self::Required),
            _ => Err(Status::InvalidOption),
        }
    }
}

impl CredProtect {
    /// Assertion-candidate filter only. user_verified is the actual result of
    /// backend verification, never the client's requested UV option. A true
    /// result does not replace UP, RP binding, requested UV, or token checks.
    /// Exclude-list processing follows its own makeCredential algorithm.
    pub fn permits_assertion(self, user_verified: bool, id_in_allow_list: bool) -> bool {
        match self {
            Self::Optional => true,
            Self::OptionalWithCredentialIdList => user_verified || id_in_allow_list,
            Self::Required => user_verified,
        }
    }
}

pub struct HmacSecretInput<'a> {
    /// Decoder must validate COSE kty=2, crv=1, alg=-25 before constructing
    /// this SEC1 point. Agreement additionally verifies curve membership.
    pub key_agreement: &'a [u8; 65],
    pub salt_enc: &'a [u8],
    pub salt_auth: &'a [u8],
    /// An absent protocol means 1; this profile only supports explicit 2.
    pub protocol: Option<u8>,
}

/// Values supplied by the trusted assertion handler after enforcing the
/// command's authorization rules. This helper does not verify a PIN or button.
pub struct AssertionEvidence {
    pub user_presence_requested: bool,
    pub user_present: bool,
    pub user_verified: bool,
}

/// Per-credential secrets: with-UV first, without-UV second. Persist both with
/// the encrypted credential, including in authorized backups. Never regenerate
/// on boot or share between credentials. No Debug or Clone implementation.
pub struct HmacSecret(Zeroizing<[u8; 64]>);

impl HmacSecret {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = Zeroizing::new([0; 64]);
        rng.fill_bytes(&mut bytes[..]);
        Self(bytes)
    }
    pub fn from_bytes(bytes: Zeroizing<[u8; 64]>) -> Self {
        Self(bytes)
    }
    /// For encrypted persistence only; never log these bytes.
    pub fn storage_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Backend must already have selected an eligible credential and completed
    /// requested UV/UP. Flags here are actual backend results, not client input.
    /// Authenticate saltEnc before CBC decryption. Returns encrypted HMAC output
    /// only; all scratch secrets and any failed output are wiped.
    pub fn process(
        &self,
        authenticator_key: &PinUvKeyAgreement,
        input: HmacSecretInput<'_>,
        evidence: AssertionEvidence,
        rng: &mut impl CryptoRngCore,
        output: &mut [u8],
    ) -> Result<usize> {
        output.zeroize();
        let result = (|| {
            if input.protocol != Some(PROTOCOL_TWO) {
                return Err(Status::PinAuthInvalid);
            }
            if !evidence.user_presence_requested {
                return Err(Status::UnsupportedOption);
            }
            if !evidence.user_present {
                return Err(Status::OperationDenied);
            }
            let shared = authenticator_key
                .agree(input.key_agreement, PinUvProtocol::Two)
                .map_err(|_| Status::InvalidParameter)?;
            shared
                .verify_authentication(input.salt_enc, input.salt_auth)
                .map_err(|_| Status::PinAuthInvalid)?;
            let mut salts = Zeroizing::new([0; 64]);
            let len = shared
                .decrypt(input.salt_enc, &mut salts[..])
                .map_err(|_| Status::InvalidParameter)?;
            if len != 32 && len != 64 {
                return Err(Status::InvalidParameter);
            }
            let secret = if evidence.user_verified {
                &self.0[..32]
            } else {
                &self.0[32..]
            };
            let mut values = Zeroizing::new([0; 64]);
            for offset in (0..len).step_by(32) {
                let value = Zeroizing::new(hmac_sha256(secret, &salts[offset..offset + 32]));
                values[offset..offset + 32].copy_from_slice(&value[..]);
            }
            shared
                .encrypt(rng, &values[..len], output)
                .map_err(|_| Status::Other)
        })();
        if result.is_err() {
            output.zeroize();
        }
        result
    }
}
