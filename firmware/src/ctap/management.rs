//! PIN-authorized resident management. Cursor state is bound to the owning
//! Session; it never treats caller continuation parameters as authorization.
use super::{
    Result, Status,
    cbor::Encoder,
    credential_management::{Request, Subcommand},
    pin_session::Session,
};
use crate::storage::credentials::{Credential, MAX_DISCOVERABLE, Repository};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;
pub(crate) enum Kind {
    Rps,
    Credentials([u8; 32]),
}
pub(crate) struct Continuation {
    kind: Kind,
    cursor: u16,
    deadline: u64,
}
pub fn is_next(request: &Request<'_>) -> bool {
    matches!(
        request.subcommand,
        Subcommand::EnumerateRpsNext | Subcommand::EnumerateCredentialsNext
    )
}
async fn count<R: CryptoRngCore>(
    repo: &mut Repository<'_, '_, '_, '_, R>,
    filter: Option<&[u8; 32]>,
    unique: bool,
) -> Result<usize> {
    let mut cursor = 0;
    let mut n = 0;
    while repo
        .next_resident(&mut cursor, filter, unique)
        .await?
        .is_some()
    {
        n += 1;
    }
    Ok(n)
}
pub async fn handle<R: CryptoRngCore>(
    repo: &mut Repository<'_, '_, '_, '_, R>,
    request: Request<'_>,
    session: &mut Session,
    now: u64,
    output: &mut [u8],
    clock: &impl Fn() -> u64,
) -> Result<usize> {
    if output.len() < 768 {
        return Err(Status::Other);
    }
    if is_next(&request) {
        let mut state = session.management.take().ok_or(Status::NotAllowed)?;
        if now >= state.deadline {
            return Err(Status::NotAllowed);
        }
        let matches = matches!(
            (&state.kind, request.subcommand),
            (Kind::Rps, Subcommand::EnumerateRpsNext)
                | (Kind::Credentials(_), Subcommand::EnumerateCredentialsNext)
        );
        if !matches {
            return Err(Status::NotAllowed);
        }
        session.management_scope(None, now)?;
        let (filter, unique) = match &state.kind {
            Kind::Rps => (None, true),
            Kind::Credentials(rp) => (Some(rp), false),
        };
        let record = repo
            .next_resident(&mut state.cursor, filter, unique)
            .await?
            .ok_or(Status::NotAllowed)?;
        let n = match state.kind {
            Kind::Rps => rp_response(&record, None, output)?,
            Kind::Credentials(_) => credential_response(&record, None, output)?,
        };
        state.deadline = now.max(clock()).saturating_add(30_000);
        session.management = Some(state);
        return Ok(n);
    }
    session.clear_management();
    // Authenticate the exact canonical input, including unknown parameters.
    let mut authenticated = Zeroizing::new([0; 1024]);
    authenticated[0] = request.subcommand as u8;
    let params = request.encoded_subcommand_params.unwrap_or(&[]);
    if params.len() > 1023 {
        return Err(Status::RequestTooLarge);
    }
    authenticated[1..params.len() + 1].copy_from_slice(params);
    session.authorize_management(&request.auth, &authenticated[..params.len() + 1], now)?;
    match request.subcommand {
        Subcommand::GetMetadata => {
            session.management_scope(None, now)?;
            let total = count(repo, None, false).await?;
            let maximum = 256 * MAX_DISCOVERABLE;
            #[cfg(target_os = "none")]
            let maximum = maximum.min(crate::storage::STORAGE_SIZE / 800);
            let mut e = Encoder::new(output);
            e.map(2)?;
            e.unsigned(1)?;
            e.unsigned(total as u64)?;
            e.unsigned(2)?;
            e.unsigned(maximum.saturating_sub(total) as u64)?;
            Ok(e.len())
        }
        Subcommand::EnumerateRpsBegin => {
            session.management_scope(None, now)?;
            let total = count(repo, None, true).await?;
            let mut cursor = 0;
            let record = repo
                .next_resident(&mut cursor, None, true)
                .await?
                .ok_or(Status::NoCredentials)?;
            let n = rp_response(&record, Some(total), output)?;
            if total > 1 {
                session.management = Some(Continuation {
                    kind: Kind::Rps,
                    cursor,
                    deadline: now.max(clock()).saturating_add(30_000),
                });
            }
            Ok(n)
        }
        Subcommand::EnumerateCredentialsBegin => {
            session.management_scope(None, now)?;
            let rp = request.rp_id_hash.ok_or(Status::MissingParameter)?;
            let total = count(repo, Some(rp), false).await?;
            let mut cursor = 0;
            let record = repo
                .next_resident(&mut cursor, Some(rp), false)
                .await?
                .ok_or(Status::NoCredentials)?;
            let n = credential_response(&record, Some(total), output)?;
            if total > 1 {
                session.management = Some(Continuation {
                    kind: Kind::Credentials(*rp),
                    cursor,
                    deadline: now.max(clock()).saturating_add(30_000),
                });
            }
            Ok(n)
        }
        Subcommand::DeleteCredential | Subcommand::UpdateUserInformation => {
            let descriptor = request.credential.ok_or(Status::MissingParameter)?;
            if descriptor.credential_type != "public-key" {
                return Err(Status::InvalidParameter);
            }
            let record = repo
                .resident_by_id(descriptor.id)
                .await?
                .ok_or(Status::NoCredentials)?;
            session.management_scope(Some(record.rp_id_hash()), now.max(clock()))?;
            if request.subcommand == Subcommand::DeleteCredential {
                if !repo.delete(record.id(), record.rp_id_hash()).await? {
                    return Err(Status::NoCredentials);
                }
            } else {
                let user = request.user.ok_or(Status::MissingParameter)?;
                repo.update_user_information(
                    record.id(),
                    record.rp_id_hash(),
                    user.id,
                    user.name,
                    user.display_name,
                )
                .await?;
            }
            Ok(0)
        }
        _ => Err(Status::InvalidSubcommand),
    }
}
fn user(e: &mut Encoder<'_>, record: &Credential) -> Result<()> {
    e.map(1 + usize::from(record.name().is_some()) + usize::from(record.display_name().is_some()))?;
    e.text("id")?;
    e.bytes(record.user_id())?;
    if let Some(name) = record.name() {
        e.text("name")?;
        e.text(name)?;
    }
    if let Some(name) = record.display_name() {
        e.text("displayName")?;
        e.text(name)?;
    }
    Ok(())
}
fn rp_response(record: &Credential, total: Option<usize>, output: &mut [u8]) -> Result<usize> {
    let mut e = Encoder::new(output);
    e.map(2 + usize::from(total.is_some()))?;
    e.unsigned(3)?;
    e.map(1 + usize::from(record.rp_name().is_some()))?;
    e.text("id")?;
    e.text(record.rp_id().ok_or(Status::IntegrityFailure)?)?;
    if let Some(name) = record.rp_name() {
        e.text("name")?;
        e.text(name)?;
    }
    e.unsigned(4)?;
    e.bytes(record.rp_id_hash())?;
    if let Some(total) = total {
        e.unsigned(5)?;
        e.unsigned(total as u64)?;
    }
    Ok(e.len())
}
fn credential_response(
    record: &Credential,
    total: Option<usize>,
    output: &mut [u8],
) -> Result<usize> {
    let mut e = Encoder::new(output);
    e.map(4 + usize::from(total.is_some()))?;
    e.unsigned(6)?;
    user(&mut e, record)?;
    e.unsigned(7)?;
    e.map(2)?;
    e.text("id")?;
    e.bytes(record.id())?;
    e.text("type")?;
    e.text("public-key")?;
    let public = record.public_key()?;
    e.unsigned(8)?;
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
    if let Some(total) = total {
        e.unsigned(9)?;
        e.unsigned(total as u64)?;
    }
    e.unsigned(10)?;
    e.unsigned(u64::from(record.cred_protect()))?;
    Ok(e.len())
}
