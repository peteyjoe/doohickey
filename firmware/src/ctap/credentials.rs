//! Borrowed command models. They carry decoded input, not proof of validation
//! or authorization. Handlers must follow the CTAP algorithm's validation order.
//! No Debug implementation: these inputs can include account information.

use super::{
    extensions::{CredProtect, HmacSecretInput},
    pin_uv::AuthParameters,
    status::{Result, Status},
};

pub const ES256: i32 = -7;

pub struct RelyingParty<'a> {
    /// Preserve the full identifier for comparisons; never match a UI truncation.
    pub id: &'a str,
    pub name: Option<&'a str>,
}

pub struct User<'a> {
    /// Opaque account identifier; names are not account keys.
    pub id: &'a [u8],
    pub name: Option<&'a str>,
    pub display_name: Option<&'a str>,
}

pub struct Descriptor<'a> {
    pub credential_type: &'a str,
    pub id: &'a [u8],
}

pub struct Parameter<'a> {
    pub credential_type: &'a str,
    pub algorithm: i32,
}

/// Select the first supported public-key algorithm. Other algorithms may be
/// present in a preference list; they do not make the entire list invalid.
pub fn select_algorithm(parameters: &[Parameter<'_>]) -> Result<i32> {
    parameters
        .iter()
        .find(|parameter| parameter.credential_type == "public-key" && parameter.algorithm == ES256)
        .map(|parameter| parameter.algorithm)
        .ok_or(Status::UnsupportedAlgorithm)
}

#[derive(Default)]
pub struct MakeExtensions {
    pub cred_protect: Option<CredProtect>,
    /// None means absent; false remains distinguishable for input validation.
    pub hmac_secret: Option<bool>,
}

#[derive(Clone, Copy)]
pub struct MakeOptions {
    pub resident_key: bool,
    pub user_presence: bool,
    /// Preserve presence: this profile has no built-in UV, so the handler must
    /// distinguish an unsupported explicit option from an omitted option.
    pub user_verification: Option<bool>,
}

impl Default for MakeOptions {
    fn default() -> Self {
        Self {
            resident_key: false,
            user_presence: true,
            user_verification: None,
        }
    }
}

pub struct MakeCredential<'a> {
    pub client_data_hash: &'a [u8; 32],
    pub rp: RelyingParty<'a>,
    pub user: User<'a>,
    pub parameters: &'a [Parameter<'a>],
    /// A present empty list is invalid; absence must remain distinguishable.
    pub exclude_list: Option<&'a [Descriptor<'a>]>,
    pub options: MakeOptions,
    pub auth: AuthParameters<'a>,
    pub extensions: MakeExtensions,
    /// Retain unsupported requests so the handler can reject them correctly.
    /// This profile does not implement enterprise attestation.
    pub enterprise_attestation: Option<u32>,
    pub attestation_formats_preference: &'a [&'a str],
}

#[derive(Clone, Copy)]
pub struct AssertionOptions {
    /// rk is forbidden on getAssertion, even when false. Retain its presence
    /// so the handler rejects it at the correct point in the algorithm.
    pub resident_key: Option<bool>,
    pub user_presence: bool,
    pub user_verification: Option<bool>,
}

impl Default for AssertionOptions {
    fn default() -> Self {
        Self {
            resident_key: None,
            user_presence: true,
            user_verification: None,
        }
    }
}

pub struct GetAssertion<'a> {
    pub rp_id: &'a str,
    pub client_data_hash: &'a [u8; 32],
    /// None permits discovery; Some(empty) is invalid input, not discovery.
    pub allow_list: Option<&'a [Descriptor<'a>]>,
    pub options: AssertionOptions,
    pub auth: AuthParameters<'a>,
    pub hmac_secret: Option<HmacSecretInput<'a>>,
}
