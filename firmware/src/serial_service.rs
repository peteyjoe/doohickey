//! Experimental alpha backup interface. Trusted USB bootstrap, one paired client.
use crate::{
    ctap::{self, authenticator::Presence},
    init::{Coordinator, DeviceBackend},
    storage::{EncryptedStorage, RecordKind},
};
use doohickey_crypto::{
    ctap::hmac_sha256,
    secrets::{MasterKey, SecretBox},
};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};
const PAIR: u32 = 0x0500_0000;
const MAX: usize = 32768 + 41;
pub struct Service {
    challenge: Option<([u8; 32], u64)>,
    session: Option<MasterKey>,
    deadline: u64,
    sequence: u32,
    permissions: u8,
    grant_until: u64,
    bytes: Zeroizing<[u8; MAX]>,
    length: usize,
    offset: usize,
    backup_key: Option<MasterKey>,
    importing: bool,
}
impl Default for Service {
    fn default() -> Self {
        Self {
            challenge: None,
            session: None,
            deadline: 0,
            sequence: 0,
            permissions: 0,
            grant_until: 0,
            bytes: Zeroizing::new([0; MAX]),
            length: 0,
            offset: 0,
            backup_key: None,
            importing: false,
        }
    }
}
impl Service {
    pub fn expire(&mut self, now: u64) {
        if self.session.is_some() && now >= self.deadline {
            self.invalidate();
        }
    }
    pub fn invalidate(&mut self) {
        self.challenge = None;
        self.session = None;
        self.permissions = 0;
        self.bytes.zeroize();
        self.length = 0;
        self.offset = 0;
        self.backup_key = None;
        self.importing = false;
    }
    pub async fn handle(
        &mut self,
        c: &mut Coordinator<DeviceBackend<'_>>,
        rng: &mut impl CryptoRngCore,
        p: &mut impl Presence,
        input: &[u8],
        out: &mut [u8],
    ) -> ctap::Result<usize> {
        let result = self.dispatch(c, rng, p, input, out).await;
        if result.is_err() {
            self.invalidate();
            out.zeroize();
        }
        result
    }
    async fn dispatch(
        &mut self,
        c: &mut Coordinator<DeviceBackend<'_>>,
        rng: &mut impl CryptoRngCore,
        p: &mut impl Presence,
        input: &[u8],
        out: &mut [u8],
    ) -> ctap::Result<usize> {
        use ctap::Status::OperationDenied as Denied;
        if input.starts_with(b"PAIR") && input.len() == 36 {
            self.invalidate();
            p.confirm().await?;
            let (backend, state) = c.application_parts().ok_or(Denied)?;
            EncryptedStorage::new(backend.storage(), state.credential_key(), rng)
                .store(PAIR, RecordKind::PairingKey, &input[4..])
                .await
                .map_err(|_| Denied)?;
            out[..2].copy_from_slice(b"OK");
            return Ok(2);
        }
        if input == b"AUTH" {
            self.invalidate();
            let mut challenge = [0; 32];
            rng.try_fill_bytes(&mut challenge).map_err(|_| Denied)?;
            out[..32].copy_from_slice(&challenge);
            self.challenge = Some((challenge, p.now_ms() + 30_000));
            return Ok(32);
        }
        if input.starts_with(b"PROVE") && input.len() == 37 {
            let (challenge, deadline) = self.challenge.take().ok_or(Denied)?;
            if p.now_ms() > deadline {
                return Err(Denied);
            }
            let (backend, state) = c.application_parts().ok_or(Denied)?;
            let mut pair = Zeroizing::new([0; 32]);
            if EncryptedStorage::new(backend.storage(), state.credential_key(), rng)
                .read(PAIR, RecordKind::PairingKey, &mut pair[..])
                .await
                .map_err(|_| Denied)?
                != Some(32)
            {
                return Err(Denied);
            }
            if !bool::from(hmac_sha256(&pair[..], &challenge).ct_eq(&input[5..])) {
                return Err(Denied);
            }
            let mut message = [0; 39];
            message[..7].copy_from_slice(b"session");
            message[7..].copy_from_slice(&challenge);
            self.session = Some(MasterKey::from_bytes(Zeroizing::new(hmac_sha256(
                &pair[..],
                &message,
            ))));
            self.sequence = 0;
            self.deadline = p.now_ms() + 300_000;
            // Key confirmation encrypted with the new session key.
            return self.reply(rng, b"OK", out);
        }
        if input.first() != Some(&0x80) || p.now_ms() >= self.deadline || self.sequence >= 4096 {
            return Err(Denied);
        }
        let mut plain = Zeroizing::new([0; 1024]);
        let n = SecretBox::from_master_key(self.session.as_ref().ok_or(Denied)?)
            .open(b"serial client v1", &input[1..], &mut plain[..])
            .map_err(|_| Denied)?;
        if n < 5 || plain[..4] != self.sequence.to_le_bytes() {
            return Err(Denied);
        }
        self.sequence += 1;
        let cmd = plain[4];
        let data = &plain[5..n];
        if cmd == 1 && data.len() == 1 && matches!(data[0], 1..=3) {
            p.confirm().await?;
            self.permissions = data[0];
            self.grant_until = p.now_ms() + 120_000;
            return self.reply(rng, b"OK", out);
        }
        if p.now_ms() >= self.grant_until {
            return Err(Denied);
        }
        match cmd {
            2 if self.permissions & 1 != 0 && data.len() == 32 => {
                self.permissions = 0;
                self.bytes.zeroize();
                let mut snapshot = Zeroizing::new([0; 32768]);
                let (backend, state) = c.application_parts().ok_or(Denied)?;
                let n = backend
                    .storage()
                    .snapshot(
                        state.credential_key().provisioning_bytes(),
                        &mut snapshot[..],
                    )
                    .await
                    .map_err(|_| Denied)?;
                let key = MasterKey::from_bytes(Zeroizing::new(data.try_into().unwrap()));
                self.length = SecretBox::from_master_key(&key)
                    .seal(rng, b"backup v1", &snapshot[..n], &mut self.bytes[..])
                    .map_err(|_| Denied)?;
                self.permissions = 4;
                self.importing = false;
                self.reply(rng, &(self.length as u32).to_le_bytes(), out)
            }
            3 if self.permissions == 4 && !self.importing && data.len() == 4 => {
                let offset = u32::from_le_bytes(data.try_into().unwrap()) as usize;
                if offset >= self.length {
                    return Err(Denied);
                }
                let end = (offset + 800).min(self.length);
                let mut chunk = Zeroizing::new([0; 800]);
                chunk[..end - offset].copy_from_slice(&self.bytes[offset..end]);
                self.reply(rng, &chunk[..end - offset], out)
            }
            4 if self.permissions & 2 != 0 && data.len() == 36 => {
                let n = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
                if !(81..=MAX).contains(&n) {
                    return Err(Denied);
                }
                self.length = n;
                self.offset = 0;
                self.bytes.zeroize();
                self.backup_key = Some(MasterKey::from_bytes(Zeroizing::new(
                    data[4..].try_into().unwrap(),
                )));
                self.importing = true;
                self.permissions = 8;
                self.reply(rng, b"OK", out)
            }
            5 if self.permissions == 8 && self.importing && data.len() > 4 => {
                let offset = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
                if offset != self.offset || offset + data.len() - 4 > self.length {
                    return Err(Denied);
                }
                self.bytes[offset..offset + data.len() - 4].copy_from_slice(&data[4..]);
                self.offset += data.len() - 4;
                self.reply(rng, b"OK", out)
            }
            6 if self.permissions == 8
                && self.importing
                && self.offset == self.length
                && data.is_empty() =>
            {
                let mut snapshot = Zeroizing::new([0; 32768]);
                let n = SecretBox::from_master_key(self.backup_key.as_ref().ok_or(Denied)?)
                    .open(b"backup v1", &self.bytes[..self.length], &mut snapshot[..])
                    .map_err(|_| Denied)?;
                crate::storage::backup::validate(&snapshot[..n]).map_err(|_| Denied)?;
                p.confirm().await?;
                if p.cancelled() || p.now_ms() >= self.grant_until || p.now_ms() >= self.deadline {
                    return Err(Denied);
                }
                c.restore_backup(&snapshot[..n], rng)
                    .await
                    .map_err(|_| Denied)?;
                let result = self.reply(rng, b"OK", out);
                self.invalidate();
                result
            }
            _ => Err(Denied),
        }
    }
    fn reply(
        &self,
        rng: &mut impl CryptoRngCore,
        data: &[u8],
        out: &mut [u8],
    ) -> ctap::Result<usize> {
        let mut plain = Zeroizing::new([0; 1024]);
        plain[..4].copy_from_slice(&self.sequence.to_le_bytes());
        plain[4..4 + data.len()].copy_from_slice(data);
        out[0] = 0x80;
        SecretBox::from_master_key(self.session.as_ref().ok_or(ctap::Status::OperationDenied)?)
            .seal(
                rng,
                b"serial device v1",
                &plain[..4 + data.len()],
                &mut out[1..],
            )
            .map(|n| n + 1)
            .map_err(|_| ctap::Status::Other)
    }
}
