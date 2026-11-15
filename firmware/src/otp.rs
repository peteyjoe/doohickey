//! Typed, write-once storage for the device master key and secure-boot public
//! key hash. No generic row writes, private boot signing keys, erase, fallback,
//! or automatic key generation. See otp/README.md before provisioning hardware.
//!
//! Default: guarded ECC hardware reads; writes require `otp-provisioning`.
//! `insecure-test-otp`: flash-backed emulation only, never touches real OTP.

#[cfg(all(feature = "insecure-test-otp", feature = "otp-provisioning"))]
compile_error!("insecure-test-otp and otp-provisioning are mutually exclusive");

#[path = "otp/record.rs"]
mod record;
pub use record::{BootKeyHash, Error, MasterStatus};

#[cfg(not(feature = "insecure-test-otp"))]
#[path = "otp/hardware.rs"]
mod hardware;
#[cfg(not(feature = "insecure-test-otp"))]
#[path = "otp/hardware_policy.rs"]
mod hardware_policy;
#[cfg(not(feature = "insecure-test-otp"))]
pub use hardware::Otp;

#[cfg(feature = "insecure-test-otp")]
#[path = "otp/flash.rs"]
mod flash;
#[cfg(feature = "insecure-test-otp")]
pub use flash::Otp;

pub const IS_FLASH_BACKED: bool = cfg!(feature = "insecure-test-otp");
