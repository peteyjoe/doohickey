//! ES256 registration, discovery and assertion continuations with fresh UP
//! and verified PIN grants. Authorization is never inferred from client options.
use super::{
    Request, Result, Status,
    cbor::Encoder,
    credentials::{self, GetAssertion, MakeCredential},
    pin_session::Session,
    pin_uv::Permission,
};
use crate::storage::credentials::{self as repository, Credential, Repository};
use doohickey_crypto::ctap::sha256;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, Zeroizing};
pub(crate) struct Continuation {
    ids: repository::Discovery,
    next: usize,
    rp: [u8; 32],
    hash: Zeroizing<[u8; 32]>,
    verified: bool,
    up: bool,
    deadline: u64,
}
const _: () = assert!(repository::ID_SIZE == 60);

#[allow(async_fn_in_trait)]
pub trait Presence {
    fn now_ms(&self) -> u64 {
        0
    }
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
    execute_with_session(
        repository,
        request,
        presence,
        output,
        &mut Session::default(),
        0,
    )
    .await
}

pub async fn execute_with_session<R: CryptoRngCore>(
    repository: &mut Repository<'_, '_, '_, '_, R>,
    request: Request<'_>,
    presence: &mut impl Presence,
    output: &mut [u8],
    session: &mut Session,
    now: u64,
) -> Result<usize> {
    output.zeroize();
    if !matches!(request, Request::GetNextAssertion) {
        session.clear_assertions();
    }
    let result = async {
        check_cancel(presence)?;
        let configured = session.load(repository).await?.is_some();
        match request {
            Request::ClientPin(request) => session.handle(repository, request, now, output).await,
            Request::MakeCredential(request) => {
                if request.auth.parameter == Some(&[]) {
                    presence.confirm().await?;
                    return Err(if configured {
                        Status::PinInvalid
                    } else {
                        Status::PinNotSet
                    });
                }
                let verified = session.authorize(
                    &request.auth,
                    &sha256(request.rp.id.as_bytes()),
                    request.client_data_hash,
                    Permission::MakeCredential,
                    now,
                )?;
                if configured && !verified {
                    return Err(Status::PinUvAuthTokenRequired);
                }
                {
                    let result = make(repository, request, presence, output, verified).await;
                    let expired = verified && !session.grant_valid(presence.now_ms());
                    session.consume();
                    if expired {
                        Err(Status::PinAuthInvalid)
                    } else {
                        result
                    }
                }
            }
            Request::GetAssertion(request) => {
                if request.auth.parameter == Some(&[]) {
                    presence.confirm().await?;
                    return Err(if configured {
                        Status::PinInvalid
                    } else {
                        Status::PinNotSet
                    });
                }
                let verified = session.authorize(
                    &request.auth,
                    &sha256(request.rp_id.as_bytes()),
                    request.client_data_hash,
                    Permission::GetAssertion,
                    now,
                )?;
                {
                    let result = assertion(
                        repository, request, presence, output, verified, session, now,
                    )
                    .await;
                    let expired = verified && !session.grant_valid(presence.now_ms());
                    session.consume();
                    if expired {
                        Err(Status::PinAuthInvalid)
                    } else {
                        result
                    }
                }
            }
            Request::GetInfo => super::info::encode_with_pin(output, configured),
            Request::GetNextAssertion => {
                next_assertion(repository, presence, output, session, now).await
            }
            // Reset/PIN/management must not acquire provisional success paths.
            _ => Err(Status::InvalidCommand),
        }
    }
    .await;
    if result.is_err() {
        session.consume();
        session.clear_assertions();
        output.zeroize();
    }
    result
}

async fn make<R: CryptoRngCore>(
    repository: &mut Repository<'_, '_, '_, '_, R>,
    request: MakeCredential<'_>,
    presence: &mut impl Presence,
    output: &mut [u8],
    verified: bool,
) -> Result<usize> {
    credentials::select_algorithm(request.parameters)?;
    if (request.options.user_verification == Some(true) && !verified)
        || !request.options.user_presence
    {
        return Err(Status::InvalidOption);
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
    let credential = if request.options.resident_key {
        repository
            .create_discoverable(
                request.rp.id,
                request.user.id,
                request.user.name,
                request.user.display_name,
                request.rp.name,
            )
            .await?
    } else {
        repository.create(&rp_hash, request.user.id).await?
    };
    check_cancel(presence)?;
    let mut auth_data = [0; 256];
    auth_data[..32].copy_from_slice(&rp_hash);
    auth_data[32] = 0x41 | if verified { 4 } else { 0 }; // UP + AT, never UV/BE/BS.
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
    verified: bool,
    session: &mut Session,
    now: u64,
) -> Result<usize> {
    if request.options.user_verification == Some(true) && !verified {
        return Err(Status::InvalidOption);
    }
    if request.options.resident_key.is_some() {
        return Err(Status::UnsupportedOption);
    }
    if request.rp_id.is_empty() || request.allow_list.is_some_and(|list| list.is_empty()) {
        return Err(Status::InvalidParameter);
    }
    let rp_hash = sha256(request.rp_id.as_bytes());
    let mut candidates = repository::Discovery::default();
    let discovery = request.allow_list.is_none();
    if let Some(list) = request.allow_list {
        for descriptor in list {
            if descriptor.credential_type == "public-key"
                && repository.read(descriptor.id, &rp_hash).await?.is_some()
            {
                candidates.ids[0].copy_from_slice(descriptor.id);
                candidates.len = 1;
                break;
            }
        }
    } else {
        candidates = repository.discover(&rp_hash).await?;
    }
    if candidates.len == 0 {
        return Err(Status::NoCredentials);
    }
    check_cancel(presence)?;
    if request.options.user_presence {
        presence.confirm().await?;
    }
    check_cancel(presence)?;
    let mut credential = repository
        .read(&candidates.ids[0], &rp_hash)
        .await?
        .ok_or(Status::IntegrityFailure)?;
    let result = assertion_response(
        repository,
        &mut credential,
        request.client_data_hash,
        verified,
        request.options.user_presence,
        discovery,
        (discovery && candidates.len > 1).then_some(candidates.len),
        presence,
        output,
    )
    .await?;
    if discovery && candidates.len > 1 {
        session.assertions = Some(Continuation {
            ids: candidates,
            next: 1,
            rp: rp_hash,
            hash: Zeroizing::new(*request.client_data_hash),
            verified,
            up: request.options.user_presence,
            deadline: now.max(presence.now_ms()).saturating_add(30_000),
        });
    }
    Ok(result)
}
async fn next_assertion<R: CryptoRngCore>(
    repository: &mut Repository<'_, '_, '_, '_, R>,
    presence: &impl Presence,
    output: &mut [u8],
    session: &mut Session,
    now: u64,
) -> Result<usize> {
    let mut state = session.assertions.take().ok_or(Status::NotAllowed)?;
    if now >= state.deadline || presence.now_ms() >= state.deadline || state.next >= state.ids.len {
        return Err(Status::NotAllowed);
    }
    let mut credential = repository
        .read(&state.ids.ids[state.next], &state.rp)
        .await?
        .ok_or(Status::IntegrityFailure)?;
    let n = assertion_response(
        repository,
        &mut credential,
        &state.hash,
        state.verified,
        state.up,
        true,
        None,
        presence,
        output,
    )
    .await?;
    state.next += 1;
    state.deadline = now.max(presence.now_ms()).saturating_add(30_000);
    if state.next < state.ids.len {
        session.assertions = Some(state);
    }
    Ok(n)
}
#[allow(clippy::too_many_arguments)]
async fn assertion_response<R: CryptoRngCore>(
    repository: &mut Repository<'_, '_, '_, '_, R>,
    credential: &mut Credential,
    hash: &[u8; 32],
    verified: bool,
    up: bool,
    user: bool,
    count: Option<usize>,
    presence: &impl Presence,
    output: &mut [u8],
) -> Result<usize> {
    if output.len() < if user { 512 } else { 256 } {
        return Err(Status::Other);
    }
    check_cancel(presence)?;
    let counter = repository.advance_counter(credential).await?;
    check_cancel(presence)?;
    let mut auth = [0; 37];
    auth[..32].copy_from_slice(credential.rp_id_hash());
    auth[32] = u8::from(up) | if verified { 4 } else { 0 };
    auth[33..].copy_from_slice(&counter.to_be_bytes());
    let mut signature = Zeroizing::new([0; 72]);
    let n = sign(credential, &auth, hash, &mut signature[..])?;
    let mut e = Encoder::new(output);
    e.map(3 + usize::from(user) + usize::from(count.is_some()))?;
    e.unsigned(1)?;
    e.map(2)?;
    e.text("id")?;
    e.bytes(credential.id())?;
    e.text("type")?;
    e.text("public-key")?;
    e.unsigned(2)?;
    e.bytes(&auth)?;
    e.unsigned(3)?;
    e.bytes(&signature[..n])?;
    if user {
        let name = verified.then(|| credential.name()).flatten();
        let display = verified.then(|| credential.display_name()).flatten();
        e.unsigned(4)?;
        e.map(1 + usize::from(name.is_some()) + usize::from(display.is_some()))?;
        e.text("id")?;
        e.bytes(credential.user_id())?;
        if let Some(name) = name {
            e.text("name")?;
            e.text(name)?;
        }
        if let Some(display) = display {
            e.text("displayName")?;
            e.text(display)?;
        }
    }
    if let Some(count) = count {
        e.unsigned(5)?;
        e.unsigned(count as u64)?;
    }
    Ok(e.len())
}
