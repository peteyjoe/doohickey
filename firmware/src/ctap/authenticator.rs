//! First operational profile: non-discoverable ES256, packed self-attestation,
//! fresh UP, no PIN/UV/extensions. Authorization is never inferred from options.
use super::{
    Request, Result, Status,
    cbor::Encoder,
    credentials::{self, GetAssertion, MakeCredential},
    pin_uv::AuthParameters,
};
use crate::storage::credentials::{self as repository, Credential, Repository};
use doohickey_crypto::ctap::sha256;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, Zeroizing};
const _: () = assert!(repository::ID_SIZE == 60);

#[allow(async_fn_in_trait)]
pub trait Presence {
    /// Fresh physical interaction for this request; no cached setup press.
    async fn confirm(&mut self) -> Result<()>;
    fn cancelled(&self) -> bool;
}
impl From<repository::Error> for Status {
    fn from(error: repository::Error) -> Self {
        match error {
            repository::Error::Full => Self::KeyStoreFull,
            repository::Error::Integrity => Self::IntegrityFailure,
            repository::Error::InvalidUser => Self::InvalidParameter,
            repository::Error::NotFound => Self::NoCredentials,
            _ => Self::Other,
        }
    }
}
fn pin(auth: &AuthParameters<'_>) -> Result<()> {
    if auth.parameter.is_some() {
        return Err(if auth.protocol.is_none() {
            Status::MissingParameter
        } else {
            Status::InvalidParameter
        });
    }
    Ok(())
}
fn check_cancel(presence: &impl Presence) -> Result<()> {
    if presence.cancelled() {
        Err(Status::KeepaliveCancel)
    } else {
        Ok(())
    }
}

/// Called by the single storage owner. Await to completion even after cancel;
/// never put a timeout/select around the mutation future. Errors wipe output.
pub async fn execute<R: CryptoRngCore>(
    repository: &mut Repository<'_, '_, '_, '_, R>,
    request: Request<'_>,
    presence: &mut impl Presence,
    output: &mut [u8],
) -> Result<usize> {
    output.zeroize();
    let result = async {
        check_cancel(presence)?;
        match request {
            Request::MakeCredential(request) => make(repository, request, presence, output).await,
            Request::GetAssertion(request) => {
                assertion(repository, request, presence, output).await
            }
            Request::GetInfo => super::info::encode_for_authenticator(output),
            Request::GetNextAssertion => Err(Status::NotAllowed),
            // Reset/PIN/management must not acquire provisional success paths.
            _ => Err(Status::InvalidCommand),
        }
    }
    .await;
    if result.is_err() {
        output.zeroize();
    }
    result
}

async fn make<R: CryptoRngCore>(
    repository: &mut Repository<'_, '_, '_, '_, R>,
    request: MakeCredential<'_>,
    presence: &mut impl Presence,
    output: &mut [u8],
) -> Result<usize> {
    pin(&request.auth)?;
    credentials::select_algorithm(request.parameters)?;
    if request.options.user_verification == Some(true) || !request.options.user_presence {
        return Err(Status::InvalidOption);
    }
    if request.options.resident_key {
        return Err(Status::UnsupportedOption);
    }
    if request.enterprise_attestation.is_some() {
        return Err(Status::InvalidParameter);
    }
    if request.rp.id.is_empty() || request.exclude_list.is_some_and(|list| list.is_empty()) {
        return Err(Status::InvalidParameter);
    }
    if output.len() < 384 {
        return Err(Status::Other);
    }
    let rp_hash = sha256(request.rp.id.as_bytes());
    if let Some(list) = request.exclude_list {
        for descriptor in list {
            if descriptor.credential_type == "public-key"
                && repository.read(descriptor.id, &rp_hash).await?.is_some()
            {
                // Exclusion is disclosed only after a presence attempt, even
                // when that attempt expires, per the command algorithm.
                if presence.confirm().await == Err(Status::KeepaliveCancel) {
                    return Err(Status::KeepaliveCancel);
                }
                check_cancel(presence)?;
                return Err(Status::CredentialExcluded);
            }
        }
    }
    presence.confirm().await?;
    check_cancel(presence)?;
    let credential = repository.create(&rp_hash, request.user.id).await?;
    check_cancel(presence)?;
    let mut auth_data = [0; 256];
    auth_data[..32].copy_from_slice(&rp_hash);
    auth_data[32] = 0x41; // UP + AT, never UV/BE/BS.
    auth_data[37..53].copy_from_slice(&super::info::DEVELOPMENT_AAGUID);
    auth_data[53..55].copy_from_slice(&(repository::ID_SIZE as u16).to_be_bytes());
    auth_data[55..115].copy_from_slice(credential.id());
    let public = credential.public_key()?;
    let mut e = Encoder::new(&mut auth_data[115..]);
    e.map(5)?;
    e.unsigned(1)?;
    e.unsigned(2)?;
    e.unsigned(3)?;
    e.integer(-7)?;
    e.integer(-1)?;
    e.unsigned(1)?;
    e.integer(-2)?;
    e.bytes(&public[1..33])?;
    e.integer(-3)?;
    e.bytes(&public[33..])?;
    let auth_len = 115 + e.len();
    // Honor a supported preference; unsupported formats do not forbid the
    // default packed self-attestation. No device-wide attestation key exists.
    let none = request
        .attestation_formats_preference
        .iter()
        .find(|f| matches!(**f, "none" | "packed"))
        == Some(&"none");
    let mut signature = Zeroizing::new([0; 72]);
    let signature_len = if none {
        0
    } else {
        sign(
            &credential,
            &auth_data[..auth_len],
            request.client_data_hash,
            &mut signature[..],
        )?
    };
    let mut e = Encoder::new(output);
    e.map(3)?;
    e.unsigned(1)?;
    e.text(if none { "none" } else { "packed" })?;
    e.unsigned(2)?;
    e.bytes(&auth_data[..auth_len])?;
    e.unsigned(3)?;
    e.map(if none { 0 } else { 2 })?;
    if !none {
        e.text("alg")?;
        e.integer(-7)?;
        e.text("sig")?;
        e.bytes(&signature[..signature_len])?;
    }
    Ok(e.len())
}
fn sign(credential: &Credential, auth: &[u8], hash: &[u8; 32], output: &mut [u8]) -> Result<usize> {
    let mut message = Zeroizing::new([0; 288]);
    message[..auth.len()].copy_from_slice(auth);
    message[auth.len()..auth.len() + 32].copy_from_slice(hash);
    Ok(credential.sign(&message[..auth.len() + 32], output)?)
}
async fn assertion<R: CryptoRngCore>(
    repository: &mut Repository<'_, '_, '_, '_, R>,
    request: GetAssertion<'_>,
    presence: &mut impl Presence,
    output: &mut [u8],
) -> Result<usize> {
    pin(&request.auth)?;
    if request.options.user_verification == Some(true) {
        return Err(Status::InvalidOption);
    }
    if request.options.resident_key.is_some() {
        return Err(Status::UnsupportedOption);
    }
    if request.rp_id.is_empty() || request.allow_list.is_some_and(|list| list.is_empty()) {
        return Err(Status::InvalidParameter);
    }
    if output.len() < 256 {
        return Err(Status::Other);
    }
    let Some(list) = request.allow_list else {
        return Err(Status::NoCredentials);
    };
    let rp_hash = sha256(request.rp_id.as_bytes());
    let mut selected = None;
    for descriptor in list {
        if descriptor.credential_type == "public-key"
            && let Some(credential) = repository.read(descriptor.id, &rp_hash).await?
        {
            selected = Some(credential);
            break;
        }
    }
    let mut credential = selected.ok_or(Status::NoCredentials)?;
    check_cancel(presence)?;
    if request.options.user_presence {
        presence.confirm().await?;
    }
    check_cancel(presence)?;
    let counter = repository.advance_counter(&mut credential).await?;
    check_cancel(presence)?;
    let mut auth_data = [0; 37];
    auth_data[..32].copy_from_slice(&rp_hash);
    auth_data[32] = u8::from(request.options.user_presence);
    auth_data[33..].copy_from_slice(&counter.to_be_bytes());
    let mut signature = Zeroizing::new([0; 72]);
    let signature_len = sign(
        &credential,
        &auth_data,
        request.client_data_hash,
        &mut signature[..],
    )?;
    let mut e = Encoder::new(output);
    e.map(3)?;
    e.unsigned(1)?;
    e.map(2)?;
    e.text("id")?;
    e.bytes(credential.id())?;
    e.text("type")?;
    e.text("public-key")?;
    e.unsigned(2)?;
    e.bytes(&auth_data)?;
    e.unsigned(3)?;
    e.bytes(&signature[..signature_len])?;
    // Non-discoverable allow-list response: no user names/handles, no count,
    // no continuation and no assertion of UV or unsupported extension outputs.
    Ok(e.len())
}
