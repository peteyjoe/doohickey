//! Development discovery and operational ES256 profiles. Neither advertises
//! unfinished features or CTAP 2.3 conformance.
use super::{Result, cbor::Encoder};
use zeroize::Zeroize;

/// Model identifier shared by both flash geometries, not a device identity,
/// attestation certificate or release/certification identifier.
pub const DEVELOPMENT_AAGUID: [u8; 16] = *b"DOOHICKEY-DEV001";
pub const DISCOVERY_VERSION: &str = "FIDO_2_0";

pub fn encode(output: &mut [u8]) -> Result<usize> {
    encode_profile(output, false, None)
}
pub fn encode_for_authenticator(output: &mut [u8]) -> Result<usize> {
    encode_profile(output, true, None)
}
pub fn encode_with_pin(output: &mut [u8], configured: bool) -> Result<usize> {
    encode_profile(output, true, Some(configured))
}
fn encode_profile(output: &mut [u8], operational: bool, pin: Option<bool>) -> Result<usize> {
    output.zeroize();
    let result = (|| {
        let mut e = Encoder::new(output);
        e.map(if pin.is_some() {
            10
        } else if operational {
            8
        } else {
            5
        })?;
        e.unsigned(1)?;
        e.array(1)?;
        e.text(DISCOVERY_VERSION)?;
        if pin.is_some() {
            e.unsigned(2)?;
            e.array(2)?;
            e.text("credProtect")?;
            e.text("hmac-secret")?;
        }
        e.unsigned(3)?;
        e.bytes(&DEVELOPMENT_AAGUID)?;
        e.unsigned(4)?;
        e.map(if pin.is_some() { 6 } else { 3 })?;
        e.text("rk")?;
        e.boolean(pin.is_some())?;
        e.text("up")?;
        e.boolean(operational)?;
        e.text("plat")?;
        e.boolean(false)?;
        if let Some(configured) = pin {
            e.text("credMgmt")?;
            e.boolean(true)?;
            e.text("clientPin")?;
            e.boolean(configured)?;
            e.text("pinUvAuthToken")?;
            e.boolean(true)?;
        }
        e.unsigned(5)?;
        e.unsigned(super::cbor::MAX_MESSAGE_SIZE as u64)?;
        if pin.is_some() {
            e.unsigned(6)?;
            e.array(1)?;
            e.unsigned(2)?;
        }
        if operational {
            e.unsigned(7)?;
            e.unsigned(super::codec::MAX_DESCRIPTORS as u64)?;
            e.unsigned(8)?;
            e.unsigned(60)?;
        }
        e.unsigned(9)?;
        e.array(1)?;
        e.text("usb")?;
        if operational {
            e.unsigned(10)?;
            e.array(1)?;
            e.map(2)?;
            e.text("alg")?;
            e.integer(-7)?;
            e.text("type")?;
            e.text("public-key")?;
        }
        Ok(e.len())
    })();
    if result.is_err() {
        output.zeroize();
    }
    result
}
