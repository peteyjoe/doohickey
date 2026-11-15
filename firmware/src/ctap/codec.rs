//! Bounded wire-to-model decoding. Borrow request strings/bytes; fixed scratch
//! owns only list slots and an uncompressed public key. No authorization here.
use super::{
    Command, Request, Result, Status,
    cbor::{self, Value},
    credential_management,
    credentials::*,
    extensions::{CredProtect, HmacSecretInput},
    pin_uv,
};

pub const MAX_PARAMETERS: usize = 16;
pub const MAX_DESCRIPTORS: usize = 8;
pub const MAX_FORMATS: usize = 8;
pub struct Scratch<'a> {
    parameters: [Parameter<'a>; MAX_PARAMETERS],
    descriptors: [Descriptor<'a>; MAX_DESCRIPTORS],
    formats: [&'a str; MAX_FORMATS],
    point: [u8; 65],
}
impl Default for Scratch<'_> {
    fn default() -> Self {
        Self::new()
    }
}
impl Scratch<'_> {
    pub fn new() -> Self {
        Self {
            parameters: [const {
                Parameter {
                    credential_type: "",
                    algorithm: 0,
                }
            }; MAX_PARAMETERS],
            descriptors: [const {
                Descriptor {
                    credential_type: "",
                    id: &[],
                }
            }; MAX_DESCRIPTORS],
            formats: [""; MAX_FORMATS],
            point: [0; 65],
        }
    }
}
fn required(value: Option<Value<'_>>) -> Result<Value<'_>> {
    value.ok_or(Status::MissingParameter)
}
fn nested(value: Option<Value<'_>>) -> Result<Value<'_>> {
    value.ok_or(Status::CborUnexpectedType)
}
fn byte(value: Value<'_>) -> Result<u8> {
    u8::try_from(value.unsigned()?).map_err(|_| Status::InvalidParameter)
}
fn text(value: Option<Value<'_>>) -> Result<Option<&str>> {
    value.map(Value::text).transpose()
}
fn bytes(value: Option<Value<'_>>) -> Result<Option<&[u8]>> {
    value.map(Value::bytes).transpose()
}
fn boolean(value: Option<Value<'_>>) -> Result<Option<bool>> {
    value.map(Value::boolean).transpose()
}
fn hash(value: Value<'_>) -> Result<&[u8; 32]> {
    value
        .bytes()?
        .try_into()
        .map_err(|_| Status::InvalidParameter)
}
fn auth(value: Value<'_>, protocol: i64, parameter: i64) -> Result<pin_uv::AuthParameters<'_>> {
    Ok(pin_uv::AuthParameters {
        protocol: value.get_int(protocol)?.map(byte).transpose()?,
        parameter: bytes(value.get_int(parameter)?)?,
    })
}
fn rp(value: Value<'_>) -> Result<RelyingParty<'_>> {
    Ok(RelyingParty {
        id: nested(value.get_text("id")?)?.text()?,
        name: text(value.get_text("name")?)?,
    })
}
fn user(value: Value<'_>) -> Result<User<'_>> {
    let id = nested(value.get_text("id")?)?.bytes()?;
    if id.is_empty() || id.len() > 64 {
        return Err(Status::InvalidParameter);
    }
    Ok(User {
        id,
        name: text(value.get_text("name")?)?,
        display_name: text(value.get_text("displayName")?)?,
    })
}
fn descriptor(value: Value<'_>) -> Result<Descriptor<'_>> {
    Ok(Descriptor {
        credential_type: nested(value.get_text("type")?)?.text()?,
        id: nested(value.get_text("id")?)?.bytes()?,
    })
}
fn descriptors<'a>(
    value: Option<Value<'a>>,
    slots: &'a mut [Descriptor<'a>],
) -> Result<Option<&'a [Descriptor<'a>]>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let mut array = value.array()?;
    let len = array.len();
    if len > slots.len() {
        return Err(Status::RequestTooLarge);
    }
    for slot in &mut slots[..len] {
        *slot = descriptor(array.read_next()?.ok_or(Status::InvalidCbor)?)?;
    }
    Ok(Some(&slots[..len]))
}
fn point<'a>(value: Value<'_>, output: &'a mut [u8; 65]) -> Result<&'a [u8; 65]> {
    if nested(value.get_int(1)?)?.integer()? != 2
        || nested(value.get_int(3)?)?.integer()? != -25
        || nested(value.get_int(-1)?)?.integer()? != 1
    {
        return Err(Status::InvalidParameter);
    }
    let x = nested(value.get_int(-2)?)?.bytes()?;
    let y = nested(value.get_int(-3)?)?.bytes()?;
    if x.len() != 32 || y.len() != 32 {
        return Err(Status::InvalidParameter);
    }
    output[0] = 4;
    output[1..33].copy_from_slice(x);
    output[33..].copy_from_slice(y);
    doohickey_crypto::ctap::validate_key_agreement(output).map_err(|_| Status::InvalidParameter)?;
    Ok(output)
}

/// Includes the leading CTAP command byte, never the HID framing. Unknown map
/// members are ignored only AFTER full canonical syntax/resource validation.
pub fn decode<'a>(message: &'a [u8], scratch: &'a mut Scratch<'a>) -> Result<Request<'a>> {
    if message.len() > cbor::MAX_MESSAGE_SIZE {
        return Err(Status::RequestTooLarge);
    }
    let command = Command::try_from(*message.first().ok_or(Status::InvalidLength)?)?;
    if matches!(
        command,
        Command::GetInfo | Command::Reset | Command::GetNextAssertion | Command::Selection
    ) {
        if message.len() != 1 {
            return Err(Status::InvalidLength);
        }
        return Ok(match command {
            Command::GetInfo => Request::GetInfo,
            Command::Reset => Request::Reset,
            Command::GetNextAssertion => Request::GetNextAssertion,
            _ => Request::Selection,
        });
    }
    if message.len() == 1 {
        return Err(Status::MissingParameter);
    }
    let map = cbor::decode(&message[1..])?;
    map.map()?;
    match command {
        Command::MakeCredential => {
            let client_data_hash = hash(required(map.get_int(1)?)?)?;
            let rp = rp(required(map.get_int(2)?)?)?;
            let user = user(required(map.get_int(3)?)?)?;
            let mut array = required(map.get_int(4)?)?.array()?;
            let len = array.len();
            if len > MAX_PARAMETERS {
                return Err(Status::RequestTooLarge);
            }
            for slot in &mut scratch.parameters[..len] {
                let value = array.read_next()?.ok_or(Status::InvalidCbor)?;
                *slot = Parameter {
                    credential_type: nested(value.get_text("type")?)?.text()?,
                    algorithm: i32::try_from(nested(value.get_text("alg")?)?.integer()?)
                        .map_err(|_| Status::InvalidParameter)?,
                };
            }
            let mut options = MakeOptions::default();
            if let Some(value) = map.get_int(7)? {
                value.map()?;
                options.resident_key = boolean(value.get_text("rk")?)?.unwrap_or(false);
                options.user_presence = boolean(value.get_text("up")?)?.unwrap_or(true);
                options.user_verification = boolean(value.get_text("uv")?)?;
            }
            let mut extensions = MakeExtensions::default();
            if let Some(value) = map.get_int(6)? {
                value.map()?;
                extensions.cred_protect = value
                    .get_text("credProtect")?
                    .map(|v| CredProtect::try_from(byte(v)?))
                    .transpose()?;
                extensions.hmac_secret = boolean(value.get_text("hmac-secret")?)?;
            }
            let formats_len = if let Some(value) = map.get_int(11)? {
                let mut array = value.array()?;
                let count = array.len();
                if count > MAX_FORMATS {
                    return Err(Status::RequestTooLarge);
                }
                for slot in &mut scratch.formats[..count] {
                    *slot = array.read_next()?.ok_or(Status::InvalidCbor)?.text()?;
                }
                count
            } else {
                0
            };
            Ok(Request::MakeCredential(MakeCredential {
                client_data_hash,
                rp,
                user,
                parameters: &scratch.parameters[..len],
                exclude_list: descriptors(map.get_int(5)?, &mut scratch.descriptors)?,
                options,
                auth: auth(map, 9, 8)?,
                extensions,
                enterprise_attestation: map
                    .get_int(10)?
                    .map(|v| u32::try_from(v.unsigned()?).map_err(|_| Status::InvalidParameter))
                    .transpose()?,
                attestation_formats_preference: &scratch.formats[..formats_len],
            }))
        }
        Command::GetAssertion => {
            let rp_id = required(map.get_int(1)?)?.text()?;
            let client_data_hash = hash(required(map.get_int(2)?)?)?;
            let mut options = AssertionOptions::default();
            if let Some(value) = map.get_int(5)? {
                value.map()?;
                options.resident_key = boolean(value.get_text("rk")?)?;
                options.user_presence = boolean(value.get_text("up")?)?.unwrap_or(true);
                options.user_verification = boolean(value.get_text("uv")?)?;
            }
            let hmac_secret = if let Some(value) = map.get_int(4)? {
                value.map()?;
                if let Some(hmac) = value.get_text("hmac-secret")? {
                    Some(HmacSecretInput {
                        key_agreement: point(nested(hmac.get_int(1)?)?, &mut scratch.point)?,
                        salt_enc: nested(hmac.get_int(2)?)?.bytes()?,
                        salt_auth: nested(hmac.get_int(3)?)?.bytes()?,
                        protocol: hmac.get_int(4)?.map(byte).transpose()?,
                    })
                } else {
                    None
                }
            } else {
                None
            };
            Ok(Request::GetAssertion(GetAssertion {
                rp_id,
                client_data_hash,
                allow_list: descriptors(map.get_int(3)?, &mut scratch.descriptors)?,
                options,
                auth: auth(map, 7, 6)?,
                hmac_secret,
            }))
        }
        Command::ClientPin => {
            let subcommand = byte(required(map.get_int(2)?)?)?;
            if subcommand == 1 {
                return Ok(Request::ClientPin(pin_uv::Request::GetRetries));
            }
            if !matches!(subcommand, 2 | 3 | 4 | 5 | 9) {
                return Err(Status::InvalidSubcommand);
            }
            let protocol = byte(required(map.get_int(1)?)?)?;
            if subcommand == 2 {
                return Ok(Request::ClientPin(pin_uv::Request::GetKeyAgreement {
                    protocol,
                }));
            }
            let key_agreement = point(required(map.get_int(3)?)?, &mut scratch.point)?;
            Ok(Request::ClientPin(match subcommand {
                5 => pin_uv::Request::GetToken {
                    protocol,
                    key_agreement,
                    pin_hash_enc: required(map.get_int(6)?)?.bytes()?,
                },
                3 => pin_uv::Request::SetPin {
                    protocol,
                    key_agreement,
                    new_pin_enc: required(map.get_int(5)?)?.bytes()?,
                    pin_uv_auth_param: required(map.get_int(4)?)?.bytes()?,
                },
                4 => pin_uv::Request::ChangePin {
                    protocol,
                    key_agreement,
                    new_pin_enc: required(map.get_int(5)?)?.bytes()?,
                    pin_hash_enc: required(map.get_int(6)?)?.bytes()?,
                    pin_uv_auth_param: required(map.get_int(4)?)?.bytes()?,
                },
                9 => pin_uv::Request::GetTokenWithPermissions {
                    protocol,
                    key_agreement,
                    pin_hash_enc: required(map.get_int(6)?)?.bytes()?,
                    permissions: pin_uv::Permissions::from_bits(
                        required(map.get_int(9)?)?.unsigned()?,
                    )?,
                    rp_id: text(map.get_int(10)?)?,
                },
                _ => unreachable!(),
            }))
        }
        Command::CredentialManagement => {
            let subcommand =
                credential_management::Subcommand::try_from(byte(required(map.get_int(1)?)?)?)?;
            let params = map.get_int(2)?;
            if let Some(value) = params {
                value.map()?;
            }
            Ok(Request::CredentialManagement(
                credential_management::Request {
                    subcommand,
                    rp_id_hash: params
                        .map(|v| v.get_int(1))
                        .transpose()?
                        .flatten()
                        .map(hash)
                        .transpose()?,
                    credential: params
                        .map(|v| v.get_int(2))
                        .transpose()?
                        .flatten()
                        .map(descriptor)
                        .transpose()?,
                    user: params
                        .map(|v| v.get_int(3))
                        .transpose()?
                        .flatten()
                        .map(user)
                        .transpose()?,
                    auth: auth(map, 3, 4)?,
                    encoded_subcommand_params: params.map(Value::encoded),
                },
            ))
        }
        _ => unreachable!(),
    }
}
