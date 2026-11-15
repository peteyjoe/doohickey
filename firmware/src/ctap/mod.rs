//! Transport-independent CTAP 2.3 foundation for an ES256, discoverable-key,
//! ClientPIN authenticator. See README.md for implemented scope and integration.
//!
//! This is a typed command boundary, not a CBOR decoder or a working device
//! backend. No command handlers have default success implementations. A backend
//! must implement the normative command algorithms, persistence, UP/UV, timers,
//! and cancellation before exposing these commands on a transport.

pub mod commands;
pub mod credential_management;
pub mod credentials;
pub mod extensions;
pub mod pin_uv;
pub mod status;

pub use commands::{Command, Handlers, Request, RequestContext, execute};
pub use status::{Result, Status};

/// Target profile only: do not advertise it until a complete backend exists.
pub const TARGET_VERSION: &str = "FIDO_2_3";
pub const TARGET_EXTENSIONS: &[&str] = &["credProtect", "hmac-secret"];
pub const TARGET_PIN_UV_PROTOCOLS: &[u8] = &[pin_uv::PROTOCOL_TWO];
