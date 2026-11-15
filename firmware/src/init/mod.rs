//! Durable, explicitly authorized initialization. Secure-boot provisioning and
//! CTAP credential operations are separate lifecycles. See README.md.
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
pub use device::{DeviceBackend, run_setup};
