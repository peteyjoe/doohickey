//! Minimal ClientPIN/protocol-2 request boundary. Cryptographic operations live
//! in doohickey_crypto::ctap. PIN storage, retries, token issuance and lifetime
//! must be implemented together with durable state, not as stateless helpers.

use super::status::{Result, Status};

pub const PROTOCOL_TWO: u8 = 2;

/// Presence is retained independently so missing protocol/auth fields can be
/// rejected at the appropriate step of each command, including zero-length
/// pinUvAuthParam selection requests. Not a successful authorization grant.
#[derive(Default)]
pub struct AuthParameters<'a> {
    pub protocol: Option<u8>,
    pub parameter: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Permission {
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    CredentialManagement = 0x04,
}

/// Requested permissions for the minimal profile. This is NOT a verified token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions(u8);

impl Permissions {
    pub fn from_bits(bits: u64) -> Result<Self> {
        if bits == 0 {
            return Err(Status::InvalidParameter);
        }
        // Known permissions for features absent from this profile are errors.
        // Undefined bits are ignored per CTAP, including future high bits.
        if bits & 0x78 != 0 {
            return Err(Status::UnauthorizedPermission);
        }
        Ok(Self((bits & 0x07) as u8))
    }
    pub fn bits(self) -> u8 {
        self.0
    }
    pub fn contains(self, permission: Permission) -> bool {
        self.0 & permission as u8 != 0
    }
    pub fn requires_rp_id(self) -> bool {
        self.contains(Permission::MakeCredential) || self.contains(Permission::GetAssertion)
    }
}

/// SEC1 key points must come from decoded COSE keys validated as EC2/P-256,
/// alg=-25. The crypto agreement operation additionally validates the curve.
/// These requests contain encrypted PIN material and deliberately lack Debug.
pub enum Request<'a> {
    GetRetries,
    GetKeyAgreement {
        protocol: u8,
    },
    SetPin {
        protocol: u8,
        key_agreement: &'a [u8; 65],
        new_pin_enc: &'a [u8],
        pin_uv_auth_param: &'a [u8],
    },
    ChangePin {
        protocol: u8,
        key_agreement: &'a [u8; 65],
        new_pin_enc: &'a [u8],
        pin_hash_enc: &'a [u8],
        pin_uv_auth_param: &'a [u8],
    },
    GetTokenWithPermissions {
        protocol: u8,
        key_agreement: &'a [u8; 65],
        pin_hash_enc: &'a [u8],
        permissions: Permissions,
        rp_id: Option<&'a str>,
    },
}

impl Request<'_> {
    pub fn subcommand(&self) -> u8 {
        match self {
            Self::GetRetries => 0x01,
            Self::GetKeyAgreement { .. } => 0x02,
            Self::SetPin { .. } => 0x03,
            Self::ChangePin { .. } => 0x04,
            Self::GetTokenWithPermissions { .. } => 0x09,
        }
    }
}
