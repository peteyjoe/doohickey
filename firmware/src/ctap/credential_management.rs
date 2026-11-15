//! Required for this discoverable-credential profile without a built-in account
//! management UI. Continuation requests need backend-owned enumeration state.

use super::{
    credentials::{Descriptor, User},
    pin_uv::AuthParameters,
    status::{Result, Status},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Subcommand {
    GetMetadata = 0x01,
    EnumerateRpsBegin = 0x02,
    EnumerateRpsNext = 0x03,
    EnumerateCredentialsBegin = 0x04,
    EnumerateCredentialsNext = 0x05,
    DeleteCredential = 0x06,
    UpdateUserInformation = 0x07,
}

impl TryFrom<u8> for Subcommand {
    type Error = Status;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::GetMetadata),
            2 => Ok(Self::EnumerateRpsBegin),
            3 => Ok(Self::EnumerateRpsNext),
            4 => Ok(Self::EnumerateCredentialsBegin),
            5 => Ok(Self::EnumerateCredentialsNext),
            6 => Ok(Self::DeleteCredential),
            7 => Ok(Self::UpdateUserInformation),
            _ => Err(Status::InvalidSubcommand),
        }
    }
}

/// Not pre-authorized. The handler must authenticate the exact original
/// canonical subCommandParams encoding, including any unrecognized members,
/// rather than re-encoding this subset and authenticating different bytes.
pub struct Request<'a> {
    pub subcommand: Subcommand,
    pub rp_id_hash: Option<&'a [u8; 32]>,
    pub credential: Option<Descriptor<'a>>,
    pub user: Option<User<'a>>,
    pub auth: AuthParameters<'a>,
    pub encoded_subcommand_params: Option<&'a [u8]>,
}
