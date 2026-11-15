//! Protocol-2 ClientPIN. Durable attempts are consumed before PIN decryption;
//! volatile authorization is never reconstructed from flash or client options.
use super::{
    Result, Status,
    cbor::Encoder,
    pin_uv::{self, AuthParameters, Permission},
};
use crate::storage::credentials::Repository;
use doohickey_crypto::ctap::{PinUvKeyAgreement, PinUvProtocol, hmac_sha256, sha256};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
const STATE: u32 = 0x0200_0000;
const WITNESS: u32 = 0x0200_0001;
const MAGIC: &[u8; 8] = b"DOOHPIN1";
const LIFETIME: u64 = 30_000;
struct Token {
    key: Zeroizing<[u8; 32]>,
    rp: Option<[u8; 32]>,
    permissions: u8,
    deadline: u64,
}
#[derive(Default)]
pub struct Session {
    pub(crate) assertions: Option<super::authenticator::Continuation>,
    agreement: Option<PinUvKeyAgreement>,
    token: Option<Token>,
    failures: u8,
}
impl Session {
    pub fn grant_valid(&self, now: u64) -> bool {
        self.token.as_ref().is_some_and(|t| now < t.deadline)
    }
    pub fn clear_assertions(&mut self) {
        self.assertions = None;
    }
    pub fn invalidate(&mut self) {
        self.clear_assertions();
        self.token = None;
        self.agreement = None;
    }
    pub fn expire(&mut self, now: u64) {
        if self.token.as_ref().is_some_and(|t| now >= t.deadline) {
            self.token = None;
        }
    }
    pub async fn load<R: CryptoRngCore>(
        &mut self,
        repo: &mut Repository<'_, '_, '_, '_, R>,
    ) -> Result<Option<Zeroizing<[u8; 26]>>> {
        let mut bytes = Zeroizing::new([0; 26]);
        let mut witness = [0; 8];
        let n = repo.pin_read(STATE, &mut bytes[..]).await?;
        let w = repo.pin_read(WITNESS, &mut witness).await?;
        if n.is_none() && w.is_none() {
            return Ok(None);
        }
        if n != Some(26)
            || w != Some(8)
            || &witness != MAGIC
            || &bytes[..8] != MAGIC
            || bytes[24] > 8
            || !(4..=63).contains(&bytes[25])
        {
            self.invalidate();
            return Err(Status::IntegrityFailure);
        }
        Ok(Some(bytes))
    }
    pub fn authorize(
        &mut self,
        auth: &AuthParameters<'_>,
        rp: &[u8; 32],
        hash: &[u8; 32],
        permission: Permission,
        now: u64,
    ) -> Result<bool> {
        self.expire(now);
        let Some(param) = auth.parameter else {
            self.token = None;
            return Ok(false);
        };
        if auth.protocol.is_none() {
            return Err(Status::MissingParameter);
        }
        if auth.protocol != Some(2) {
            return Err(Status::InvalidParameter);
        }
        let token = self.token.as_mut().ok_or(Status::PinAuthInvalid)?;
        if param.len() != 32
            || token.permissions & permission as u8 == 0
            || token.rp.is_some_and(|bound| !bool::from(bound.ct_eq(rp)))
            || !bool::from(hmac_sha256(&token.key[..], hash).ct_eq(param))
        {
            return Err(Status::PinAuthInvalid);
        }
        token.rp = Some(*rp);
        Ok(true)
    }
    /// A successful credential operation consumes UV and permission grants.
    /// This conservative policy requires a fresh token for another operation.
    pub fn consume(&mut self) {
        self.token = None;
    }
    async fn verify<R: CryptoRngCore>(
        &mut self,
        repo: &mut Repository<'_, '_, '_, '_, R>,
        bytes: &mut [u8; 26],
        shared: &doohickey_crypto::ctap::PinUvSharedSecret,
        encrypted: &[u8],
    ) -> Result<()> {
        if bytes[24] == 0 {
            return Err(Status::PinBlocked);
        }
        if self.failures >= 3 {
            return Err(Status::PinAuthBlocked);
        }
        bytes[24] -= 1;
        repo.pin_store(STATE, bytes).await?; // Must finish before evaluating candidate.
        let mut hash = Zeroizing::new([0; 16]);
        let valid = shared.decrypt(encrypted, &mut hash[..]).ok() == Some(16)
            && bool::from(hash[..].ct_eq(&bytes[8..24]));
        if !valid {
            self.failures += 1;
            self.invalidate();
            return Err(if bytes[24] == 0 {
                Status::PinBlocked
            } else if self.failures >= 3 {
                Status::PinAuthBlocked
            } else {
                Status::PinInvalid
            });
        }
        self.failures = 0;
        bytes[24] = 8;
        repo.pin_store(STATE, bytes).await?;
        Ok(())
    }
    pub async fn handle<R: CryptoRngCore>(
        &mut self,
        repo: &mut Repository<'_, '_, '_, '_, R>,
        request: pin_uv::Request<'_>,
        now: u64,
        output: &mut [u8],
    ) -> Result<usize> {
        self.expire(now);
        let legacy = matches!(request, pin_uv::Request::GetToken { .. });
        let request = match request {
            pin_uv::Request::GetToken {
                protocol,
                key_agreement,
                pin_hash_enc,
            } => pin_uv::Request::GetTokenWithPermissions {
                protocol,
                key_agreement,
                pin_hash_enc,
                permissions: pin_uv::Permissions::from_bits(3)?,
                rp_id: None,
            },
            other => other,
        };
        let mut stored = self.load(repo).await?;
        if let pin_uv::Request::GetRetries = request {
            let mut e = Encoder::new(output);
            e.map(2)?;
            e.unsigned(3)?;
            e.unsigned(stored.as_ref().map_or(8, |s| s[24]) as u64)?;
            e.unsigned(4)?;
            e.boolean(self.failures >= 3)?;
            return Ok(e.len());
        }
        let protocol = match &request {
            pin_uv::Request::GetToken { protocol, .. }
            | pin_uv::Request::GetKeyAgreement { protocol }
            | pin_uv::Request::SetPin { protocol, .. }
            | pin_uv::Request::ChangePin { protocol, .. }
            | pin_uv::Request::GetTokenWithPermissions { protocol, .. } => *protocol,
            _ => unreachable!(),
        };
        if protocol != 2 {
            return Err(Status::InvalidParameter);
        }
        if self.agreement.is_none() {
            self.agreement =
                Some(PinUvKeyAgreement::try_generate(repo.rng()).map_err(|_| Status::Other)?);
        }
        if let pin_uv::Request::GetKeyAgreement { .. } = request {
            let point = self.agreement.as_ref().unwrap().public_key();
            let mut e = Encoder::new(output);
            e.map(1)?;
            e.unsigned(1)?;
            e.map(5)?;
            e.unsigned(1)?;
            e.unsigned(2)?;
            e.unsigned(3)?;
            e.integer(-25)?;
            e.integer(-1)?;
            e.unsigned(1)?;
            e.integer(-2)?;
            e.bytes(&point[1..33])?;
            e.integer(-3)?;
            e.bytes(&point[33..])?;
            return Ok(e.len());
        }
        let peer = match &request {
            pin_uv::Request::SetPin { key_agreement, .. }
            | pin_uv::Request::ChangePin { key_agreement, .. }
            | pin_uv::Request::GetTokenWithPermissions { key_agreement, .. } => *key_agreement,
            _ => unreachable!(),
        };
        let shared = self
            .agreement
            .as_ref()
            .unwrap()
            .agree(peer, PinUvProtocol::Two)
            .map_err(|_| Status::InvalidParameter)?;
        match request {
            pin_uv::Request::SetPin {
                new_pin_enc,
                pin_uv_auth_param,
                ..
            } => {
                if stored.is_some() {
                    return Err(Status::PinAuthInvalid);
                }
                shared
                    .verify_authentication(new_pin_enc, pin_uv_auth_param)
                    .map_err(|_| Status::PinAuthInvalid)?;
                let bytes = new_pin(&shared, new_pin_enc)?;
                repo.pin_store(WITNESS, MAGIC).await?;
                repo.pin_store(STATE, &bytes[..]).await?;
                self.invalidate();
                Ok(0)
            }
            pin_uv::Request::ChangePin {
                new_pin_enc,
                pin_hash_enc,
                pin_uv_auth_param,
                ..
            } => {
                let bytes = stored.as_mut().ok_or(Status::PinNotSet)?;
                if bytes[24] == 0 {
                    return Err(Status::PinBlocked);
                }
                if self.failures >= 3 {
                    return Err(Status::PinAuthBlocked);
                }
                let mut message = Zeroizing::new([0; 112]);
                if new_pin_enc.len() != 80 || pin_hash_enc.len() != 32 {
                    return Err(Status::InvalidParameter);
                }
                message[..80].copy_from_slice(new_pin_enc);
                message[80..].copy_from_slice(pin_hash_enc);
                shared
                    .verify_authentication(&message[..], pin_uv_auth_param)
                    .map_err(|_| Status::PinAuthInvalid)?;
                self.verify(repo, bytes, &shared, pin_hash_enc).await?;
                let new = new_pin(&shared, new_pin_enc)?;
                repo.pin_store(STATE, &new[..]).await?;
                self.invalidate();
                Ok(0)
            }
            pin_uv::Request::GetTokenWithPermissions {
                pin_hash_enc,
                permissions,
                rp_id,
                ..
            } => {
                if permissions.bits() & !3 != 0 || permissions.bits() == 0 {
                    return Err(Status::UnauthorizedPermission);
                }
                let rp = rp_id.filter(|s| !s.is_empty());
                if !legacy && rp.is_none() {
                    return Err(Status::MissingParameter);
                }
                let bytes = stored.as_mut().ok_or(Status::PinNotSet)?;
                self.verify(repo, bytes, &shared, pin_hash_enc).await?;
                self.token = None;
                let mut key = Zeroizing::new([0; 32]);
                repo.rng()
                    .try_fill_bytes(&mut key[..])
                    .map_err(|_| Status::Other)?;
                let mut encrypted = Zeroizing::new([0; 48]);
                let n = shared
                    .encrypt(repo.rng(), &key[..], &mut encrypted[..])
                    .map_err(|_| Status::Other)?;
                let mut e = Encoder::new(output);
                e.map(1)?;
                e.unsigned(2)?;
                e.bytes(&encrypted[..n])?;
                let n = e.len();
                self.token = Some(Token {
                    key,
                    rp: rp.map(|rp| sha256(rp.as_bytes())),
                    permissions: permissions.bits(),
                    deadline: now.saturating_add(LIFETIME),
                });
                Ok(n)
            }
            _ => unreachable!(),
        }
    }
}
fn new_pin(
    shared: &doohickey_crypto::ctap::PinUvSharedSecret,
    encrypted: &[u8],
) -> Result<Zeroizing<[u8; 26]>> {
    if encrypted.len() != 80 {
        return Err(Status::InvalidParameter);
    }
    let mut padded = Zeroizing::new([0; 64]);
    if shared
        .decrypt(encrypted, &mut padded[..])
        .map_err(|_| Status::PinAuthInvalid)?
        != 64
    {
        return Err(Status::InvalidParameter);
    }
    let len = padded.iter().rposition(|b| *b != 0).map_or(0, |n| n + 1);
    let pin = core::str::from_utf8(&padded[..len]).map_err(|_| Status::PinPolicyViolation)?;
    if len > 63 || pin.chars().count() < 4 || pin.contains('\0') {
        return Err(Status::PinPolicyViolation);
    }
    let mut out = Zeroizing::new([0; 26]);
    out[..8].copy_from_slice(MAGIC);
    let digest = Zeroizing::new(sha256(pin.as_bytes()));
    out[8..24].copy_from_slice(&digest[..16]);
    out[24] = 8;
    out[25] = pin.chars().count() as u8;
    Ok(out)
}
