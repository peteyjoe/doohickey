//! Development discovery only. Do not confuse parser/crypto availability with
//! a completed credential/PIN/extension backend or CTAP 2.3 conformance.
use super::{Result, cbor::Encoder};
use zeroize::Zeroize;

/// Model identifier shared by both flash geometries, not a device identity,
/// attestation certificate or release/certification identifier.
pub const DEVELOPMENT_AAGUID: [u8; 16] = *b"DOOHICKEY-DEV001";
pub const DISCOVERY_VERSION: &str = "FIDO_2_0";

pub fn encode(output: &mut [u8]) -> Result<usize> {
    output.zeroize();
    let result = (|| {
        let mut e = Encoder::new(output);
        e.map(5)?;
        e.unsigned(1)?;
        e.array(1)?;
        e.text(DISCOVERY_VERSION)?;
        e.unsigned(3)?;
        e.bytes(&DEVELOPMENT_AAGUID)?;
        e.unsigned(4)?;
        e.map(3)?;
        e.text("rk")?;
        e.boolean(false)?;
        e.text("up")?;
        e.boolean(false)?;
        e.text("plat")?;
        e.boolean(false)?;
        e.unsigned(5)?;
        e.unsigned(super::cbor::MAX_MESSAGE_SIZE as u64)?;
        e.unsigned(9)?;
        e.array(1)?;
        e.text("usb")?;
        Ok(e.len())
    })();
    if result.is_err() {
        output.zeroize();
    }
    result
}
