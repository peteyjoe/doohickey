//! Transport-independent CTAP 2.3 foundation for an ES256, discoverable-key,
//! ClientPIN authenticator. See README.md for implemented scope and integration.
//!
//! Bounded decoding and the non-discoverable ES256 registration/assertion
//! profile are implemented. PIN/UV, discovery and the full CTAP 2.3 profile
//! remain targets; advertise only the behavior actually connected to USB.

#[cfg(target_os = "none")]
pub mod authenticator;
pub mod cbor;
pub mod codec;
pub mod commands;
pub mod credential_management;
pub mod credentials;
pub mod exchange;
pub mod extensions;
pub mod info;
#[cfg(target_os = "none")]
pub mod pin_session;
pub mod pin_uv;
pub mod presence;
pub mod status;

pub use commands::{Command, Handlers, Request, RequestContext, execute};
pub use status::{Result, Status};

/// Target profile only: do not advertise it until a complete backend exists.
pub const TARGET_VERSION: &str = "FIDO_2_3";
pub const TARGET_EXTENSIONS: &[&str] = &["credProtect", "hmac-secret"];
pub const TARGET_PIN_UV_PROTOCOLS: &[u8] = &[pin_uv::PROTOCOL_TWO];
