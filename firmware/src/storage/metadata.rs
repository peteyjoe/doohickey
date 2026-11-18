//! Encoding for the reserved metadata record: magic bytes followed by the
//! UTF-8 firmware version. Both fields are stored in a single CRC-protected item.

pub const MAGIC: &[u8; 9] = b"DOOHICKEY";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub(super) const CURRENT_RECORD: &[u8] = concat!("DOOHICKEY", env!("CARGO_PKG_VERSION")).as_bytes();

#[derive(Debug, PartialEq, Eq)]
pub struct Metadata<'a> {
    pub magic: &'a [u8],
    /// Firmware version that created the record or last explicitly migrated it.
    pub version: &'a str,
}

pub(super) fn decode(bytes: &[u8]) -> Option<Metadata<'_>> {
    let version = bytes.strip_prefix(MAGIC.as_slice())?;
    let version = core::str::from_utf8(version).ok()?;
    if version.is_empty() {
        return None;
    }
    Some(Metadata {
        magic: MAGIC,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_record_uses_package_version() {
        let record = decode(CURRENT_RECORD).unwrap();
        assert_eq!(record.magic, MAGIC);
        assert_eq!(record.version, VERSION);
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn preserves_another_firmware_version() {
        let record = decode(b"DOOHICKEY0.0.1").unwrap();
        assert_eq!(record.version, "0.0.1");
    }

    #[test]
    fn rejects_missing_or_wrong_magic() {
        assert_eq!(decode(b""), None);
        assert_eq!(decode(b"FIDO"), None);
        assert_eq!(decode(b"OTHERSTORE0.1.0"), None);
    }

    #[test]
    fn rejects_missing_or_invalid_version() {
        assert_eq!(decode(b"DOOHICKEY"), None);
        assert_eq!(decode(b"DOOHICKEY\xff"), None);
    }
}
