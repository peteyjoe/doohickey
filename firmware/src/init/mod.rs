//! Durable initialization, reset and upgrade transactions. Secure-boot trust
//! provisioning stays separate; reset never programs OTP. See README.md.
pub mod lifecycle;
mod state;
pub use state::{Reason, Report, State};
mod coordinator;
pub mod presence;
pub mod records;
pub use coordinator::{
    Backend, Coordinator, Error, Partition, RootStatus, storage_version_supported,
};
#[cfg(target_os = "none")]
mod device;
#[cfg(target_os = "none")]
pub use device::DeviceBackend;
