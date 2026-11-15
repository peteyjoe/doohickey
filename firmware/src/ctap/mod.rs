//! Transport-independent CTAP 2.3 foundation for an ES256, discoverable-key,
//! ClientPIN authenticator. See README.md for implemented scope and integration.
//!
//! Bounded CBOR decoding and read-only development discovery are implemented.
//! Credential/PIN handlers still need the normative algorithms, persistence,
//! UP/UV, timers, and cancellation before advertising their capabilities.

pub mod cbor;
pub mod codec;
pub mod commands;
pub mod credential_management;
pub mod credentials;
pub mod extensions;
pub mod info;
pub mod pin_uv;
pub mod status;

pub use commands::{Command, Handlers, Request, RequestContext, execute};
pub use status::{Result, Status};

/// Target profile only: do not advertise it until a complete backend exists.
pub const TARGET_VERSION: &str = "FIDO_2_3";
pub const TARGET_EXTENSIONS: &[&str] = &["credProtect", "hmac-secret"];
pub const TARGET_PIN_UV_PROTOCOLS: &[u8] = &[pin_uv::PROTOCOL_TWO];
