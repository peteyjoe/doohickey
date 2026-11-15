//! Fixed persistent encodings; state v2 retains the v1 layout with a new guard.
//! Never renumber/reuse keys or change field meaning in place.
//! Top-level metadata still contains only magic and the firmware version.
use super::Error;
use doohickey_crypto::{ctap::sha256, secrets::MasterKey};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const JOURNAL_KEY: u32 = 0xffff_fe00;
pub const STATE_KEY: u32 = 0xffff_fe01;
pub const COMPLETION_KEY: u32 = 0xffff_fe02;
pub const JOURNAL_SIZE: usize = 57;
pub const STATE_SIZE: usize = 100;
pub const ENVELOPE_SIZE: usize = STATE_SIZE + doohickey_crypto::secrets::ENVELOPE_OVERHEAD;
pub const COMPLETION_SIZE: usize = 72;
pub const COMPLETION_ENVELOPE_SIZE: usize =
    COMPLETION_SIZE + doohickey_crypto::secrets::ENVELOPE_OVERHEAD;
pub(super) const COMPLETION_CONTEXT: &[u8] = b"DOOHICKEY initialization commit v1/fffffe02";
pub(super) const CONTEXT: &[u8] = b"DOOHICKEY initialization state v1/fffffe01";
const JOURNAL_MAGIC: &[u8; 8] = b"DOOHSET1";
const STATE_MAGIC: &[u8; 8] = b"DOOHCFG1";
const CURRENT_STATE_MAGIC: &[u8; 8] = b"DOOHCFG2";
const COMPLETE: &[u8; 8] = b"COMPLETE";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub user_presence_timeout_ms: u32,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            user_presence_timeout_ms: 30_000,
        }
    }
}
impl Settings {
    pub fn validate(self) -> Result<Self, Error> {
        if (1000..=120_000).contains(&self.user_presence_timeout_ms) {
            Ok(self)
        } else {
            Err(Error::InvalidInitialization)
        }
    }
}

/// Kept only after the complete persisted record has authenticated. No Debug or
/// Clone for secret-bearing state. This is base initialization, not CTAP readiness.
pub struct Initialized {
    settings: Settings,
    credential_key: MasterKey,
}
impl Initialized {
    pub fn settings(&self) -> Settings {
        self.settings
    }
    pub fn credential_key(&self) -> &MasterKey {
        &self.credential_key
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RootMode {
    New,
    Existing,
}
pub(super) struct Journal {
    pub mode: RootMode,
    pub id: [u8; 16],
}
impl Journal {
    pub fn encode(&self) -> [u8; JOURNAL_SIZE] {
        let mut bytes = [0; JOURNAL_SIZE];
        bytes[..8].copy_from_slice(JOURNAL_MAGIC);
        bytes[8] = if self.mode == RootMode::New { 1 } else { 2 };
        bytes[9..25].copy_from_slice(&self.id);
        let digest = sha256(&bytes[..25]);
        bytes[25..].copy_from_slice(&digest);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != JOURNAL_SIZE
            || &bytes[..8] != JOURNAL_MAGIC
            || !bool::from(sha256(&bytes[..25]).ct_eq(&bytes[25..]))
        {
            return Err(Error::InvalidInitialization);
        }
        let mode = match bytes[8] {
            1 => RootMode::New,
            2 => RootMode::Existing,
            _ => return Err(Error::InvalidInitialization),
        };
        let mut id = [0; 16];
        id.copy_from_slice(&bytes[9..25]);
        if id.iter().all(|b| *b == 0) {
            return Err(Error::InvalidInitialization);
        }
        Ok(Self { mode, id })
    }
}

pub(super) fn encode_state(journal: &Journal, key: &[u8; 32]) -> Zeroizing<[u8; STATE_SIZE]> {
    let mut bytes = Zeroizing::new([0; STATE_SIZE]);
    bytes[..8].copy_from_slice(CURRENT_STATE_MAGIC);
    bytes[8..24].copy_from_slice(&journal.id);
    bytes[24..56].copy_from_slice(&sha256(&journal.encode()));
    bytes[56..60].copy_from_slice(&Settings::default().user_presence_timeout_ms.to_le_bytes());
    bytes[60..92].copy_from_slice(key);
    bytes[92..].copy_from_slice(COMPLETE);
    bytes
}
pub(super) fn decode_state(bytes: &[u8], journal: &Journal) -> Result<Initialized, Error> {
    if bytes.len() != STATE_SIZE
        || (&bytes[..8] != STATE_MAGIC && &bytes[..8] != CURRENT_STATE_MAGIC)
        || &bytes[92..] != COMPLETE
        || !bool::from(bytes[8..24].ct_eq(&journal.id))
        || !bool::from(bytes[24..56].ct_eq(&sha256(&journal.encode())))
    {
        return Err(Error::InvalidInitialization);
    }
    let settings = Settings {
        user_presence_timeout_ms: u32::from_le_bytes(bytes[56..60].try_into().unwrap()),
    }
    .validate()?;
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&bytes[60..92]);
    if !valid_secret(&key) {
        return Err(Error::InvalidInitialization);
    }
    Ok(Initialized {
        settings,
        credential_key: MasterKey::from_bytes(key),
    })
}
pub(super) fn valid_secret(bytes: &[u8; 32]) -> bool {
    !bytes.iter().all(|b| *b == 0) && !bytes.iter().all(|b| *b == 0xff)
}

pub(super) fn completion(journal: &Journal, state_digest: &[u8; 32]) -> [u8; COMPLETION_SIZE] {
    let mut bytes = [0; COMPLETION_SIZE];
    bytes[..8].copy_from_slice(b"DOOHDONE");
    bytes[8..40].copy_from_slice(&sha256(&journal.encode()));
    bytes[40..].copy_from_slice(state_digest);
    bytes
}
