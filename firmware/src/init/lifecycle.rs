//! Pure compatibility policy and fixed encodings. Only named releases may
//! migrate; semver alone never authorizes a new persistent format.
use super::{Error, records};

pub const RECORD_KEY: u32 = 0xffff_fe03;
pub const TRANSACTION_KEY: u32 = 0xffff_fe04;
pub(super) const CONTEXT: &[u8] = b"DOOHICKEY lifecycle v1/fffffe03";
pub(super) const TRANSACTION_CONTEXT: &[u8] = b"DOOHICKEY lifecycle transaction v1/fffffe04";
pub(super) const HEADER_SIZE: usize = 49;
pub(super) const TRANSACTION_SIZE: usize =
    HEADER_SIZE + 1 + records::JOURNAL_SIZE + records::STATE_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub storage_start: u32,
    pub flash_size: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Upgrade {
    Current,
    Migrate,
    DowngradeBlocked,
    Unsupported,
}
fn version(value: &str) -> Option<[u32; 3]> {
    let mut parts = value.split('.');
    let mut out = [0; 3];
    for field in &mut out {
        let part = parts.next()?;
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        *field = part.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}
pub fn upgrade(stored: &str, running: &str) -> Upgrade {
    let (Some(old), Some(new)) = (version(stored), version(running)) else {
        return Upgrade::Unsupported;
    };
    if old > new {
        Upgrade::DowngradeBlocked
    } else if stored == running && matches!(running, "0.1.0" | "0.2.0" | "0.3.0") {
        Upgrade::Current
    } else if (stored == "0.1.0" && matches!(running, "0.2.0" | "0.3.0"))
        || (stored == "0.2.0" && running == "0.3.0")
    {
        Upgrade::Migrate
    } else {
        Upgrade::Unsupported
    }
}
pub(super) fn header(running: &str, geometry: Geometry) -> Result<[u8; HEADER_SIZE], Error> {
    if running.len() > 32 || version(running).is_none() {
        return Err(Error::UnsupportedVersion);
    }
    let mut out = [0; HEADER_SIZE];
    out[..8].copy_from_slice(b"DOOHLIF1");
    out[8] = running.len() as u8;
    out[9..9 + running.len()].copy_from_slice(running.as_bytes());
    out[41..45].copy_from_slice(&geometry.storage_start.to_le_bytes());
    out[45..49].copy_from_slice(&geometry.flash_size.to_le_bytes());
    Ok(out)
}
pub(super) fn decode_header(
    bytes: &[u8],
    running: &str,
    geometry: Geometry,
) -> Result<Upgrade, Error> {
    if bytes.len() != HEADER_SIZE || &bytes[..8] != b"DOOHLIF1" || !(1..=32).contains(&bytes[8]) {
        return Err(Error::InvalidInitialization);
    }
    let len = usize::from(bytes[8]);
    if bytes[9 + len..41].iter().any(|b| *b != 0) {
        return Err(Error::InvalidInitialization);
    }
    if bytes[41..45] != geometry.storage_start.to_le_bytes()
        || bytes[45..49] != geometry.flash_size.to_le_bytes()
    {
        return Err(Error::GeometryMismatch);
    }
    let stored =
        core::str::from_utf8(&bytes[9..9 + len]).map_err(|_| Error::InvalidInitialization)?;
    Ok(upgrade(stored, running))
}
