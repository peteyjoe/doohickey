//! Public startup diagnostics. Reports are not provisioning authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    NotChecked,
    SetupRequired,
    InitializationRequired,
    Initializing,
    Ready,
    MigrationRequired,
    RecoveryRequired,
}
impl State {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::SetupRequired => "setup_required",
            Self::InitializationRequired => "initialization_required",
            Self::Initializing => "initializing",
            Self::Ready => "ready",
            Self::MigrationRequired => "migration_required",
            Self::RecoveryRequired => "recovery_required",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    None,
    StorageErased,
    SetupInterrupted,
    FirmwareVersionMismatch,
    MissingMetadata,
    InvalidMetadata,
    StorageUnavailable,
    MasterKeyMissing,
    MasterKeyUnsealed,
    IncompleteProvisioning,
    InvalidMasterKey,
    OtpUnavailable,
    InvalidInitialization,
    AuthenticationFailed,
    ApplicationDataPresent,
    ProvisioningDisabled,
    EntropyUnavailable,
}
impl Reason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::StorageErased => "storage_erased",
            Self::SetupInterrupted => "setup_interrupted",
            Self::FirmwareVersionMismatch => "firmware_version_mismatch",
            Self::MissingMetadata => "missing_metadata",
            Self::InvalidMetadata => "invalid_metadata",
            Self::StorageUnavailable => "storage_unavailable",
            Self::MasterKeyMissing => "master_key_missing",
            Self::MasterKeyUnsealed => "master_key_unsealed",
            Self::IncompleteProvisioning => "incomplete_provisioning",
            Self::InvalidMasterKey => "invalid_master_key",
            Self::OtpUnavailable => "otp_unavailable",
            Self::InvalidInitialization => "invalid_initialization",
            Self::AuthenticationFailed => "authentication_failed",
            Self::ApplicationDataPresent => "application_data_present",
            Self::ProvisioningDisabled => "provisioning_disabled",
            Self::EntropyUnavailable => "entropy_unavailable",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub state: State,
    pub reason: Reason,
}
impl Report {
    pub const NOT_CHECKED: Self = Self {
        state: State::NotChecked,
        reason: Reason::None,
    };
    pub const fn permits_setup(self) -> bool {
        matches!(
            self.state,
            State::SetupRequired | State::InitializationRequired
        ) && !matches!(self.reason, Reason::ProvisioningDisabled)
    }
}
