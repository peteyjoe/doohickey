use super::{Backend, Coordinator, Error, Partition, Reason, Report, RootStatus, State};
use crate::{otp, storage};
use core::cell::Cell;
use doohickey_crypto::{rng::HardwareEntropy, secrets::MasterKey};
use embassy_rp::{Peri, gpio::Input, peripherals::TRNG};
use embassy_time::{Instant, Timer};

pub struct DeviceBackend<'d> {
    storage: storage::Storage<'d>,
    erased: bool,
}
impl<'d> DeviceBackend<'d> {
    pub fn new(storage: storage::Storage<'d>) -> Self {
        Self {
            storage,
            erased: false,
        }
    }
}
fn storage_error(error: storage::Error) -> Error {
    match error {
        storage::Error::MissingMetadata => Error::MissingMetadata,
        storage::Error::InvalidMetadata => Error::InvalidMetadata,
        storage::Error::BufferTooSmall { .. } => Error::InvalidInitialization,
        _ => Error::StorageUnavailable,
    }
}
fn otp_error(error: otp::Error) -> Error {
    match error {
        otp::Error::Corrupt | otp::Error::InvalidValue => Error::InvalidMasterKey,
        otp::Error::IncompleteProvisioning => Error::IncompleteProvisioning,
        otp::Error::ProvisioningDisabled => Error::ProvisioningDisabled,
        _ => Error::OtpUnavailable,
    }
}
impl Backend for DeviceBackend<'_> {
    fn now_ms(&self) -> u64 {
        Instant::now().as_millis()
    }
    fn can_program_root(&self) -> bool {
        cfg!(any(
            feature = "insecure-test-otp",
            feature = "otp-provisioning"
        ))
    }
    async fn partition(&mut self) -> Result<Partition, Error> {
        self.erased = self.storage.is_erased().await.map_err(storage_error)?;
        if self.erased {
            return Ok(Partition::Erased);
        }
        let metadata = self
            .storage
            .metadata()
            .await
            .map_err(storage_error)?
            .ok_or(Error::MissingMetadata)?;
        Ok(
            if super::storage_version_supported(metadata.version, storage::VERSION) {
                Partition::Compatible
            } else {
                Partition::DifferentVersion
            },
        )
    }
    async fn initialize_metadata(&mut self) -> Result<(), Error> {
        self.storage
            .initialize_metadata()
            .await
            .map_err(storage_error)?;
        self.erased = false;
        Ok(())
    }
    async fn only_setup_data(&mut self) -> Result<bool, Error> {
        self.storage
            .contains_only_setup_data()
            .await
            .map_err(storage_error)
    }
    async fn read(&mut self, key: u32, output: &mut [u8]) -> Result<Option<usize>, Error> {
        self.storage
            .read_initialization(key, output)
            .await
            .map_err(storage_error)
    }
    async fn store(&mut self, key: u32, value: &[u8]) -> Result<(), Error> {
        self.storage
            .store_initialization(key, value)
            .await
            .map_err(storage_error)
    }
    async fn root_status(&mut self) -> Result<RootStatus, Error> {
        #[cfg(feature = "insecure-test-otp")]
        if self.erased {
            return Ok(RootStatus::Blank);
        }
        #[cfg(feature = "insecure-test-otp")]
        let mut otp = otp::Otp::new(&mut self.storage);
        #[cfg(not(feature = "insecure-test-otp"))]
        let mut otp = otp::Otp::new().map_err(otp_error)?;
        Ok(match otp.master_key_status().await.map_err(otp_error)? {
            otp::MasterStatus::Blank => RootStatus::Blank,
            otp::MasterStatus::Unsealed => RootStatus::Unsealed,
            otp::MasterStatus::Sealed => RootStatus::Sealed,
        })
    }
    async fn load_root(&mut self) -> Result<MasterKey, Error> {
        #[cfg(feature = "insecure-test-otp")]
        let mut otp = otp::Otp::new(&mut self.storage);
        #[cfg(not(feature = "insecure-test-otp"))]
        let mut otp = otp::Otp::new().map_err(otp_error)?;
        otp.read_master_key().await.map_err(otp_error)
    }
    async fn provision_root(&mut self, key: &MasterKey) -> Result<(), Error> {
        #[cfg(feature = "insecure-test-otp")]
        let mut otp = otp::Otp::new(&mut self.storage);
        #[cfg(not(feature = "insecure-test-otp"))]
        let mut otp = otp::Otp::new().map_err(otp_error)?;
        otp.provision_master_key(key).await.map_err(otp_error)
    }
    async fn seal_root(&mut self) -> Result<(), Error> {
        #[cfg(feature = "insecure-test-otp")]
        let mut otp = otp::Otp::new(&mut self.storage);
        #[cfg(not(feature = "insecure-test-otp"))]
        let mut otp = otp::Otp::new().map_err(otp_error)?;
        otp.seal_master_key().await.map_err(otp_error)
    }
}

/// Core-0 application task, joined with USB so diagnostics remain live while
/// waiting for confirmation. It never times out/cancels a storage/OTP future.
pub async fn run_setup(
    coordinator: &mut Coordinator<DeviceBackend<'_>>,
    button: Input<'static>,
    trng: Peri<'static, TRNG>,
    report: &Cell<Report>,
) -> ! {
    let mut entropy = HardwareEntropy::new(trng);
    let mut gate = super::presence::PresenceGate::new(Instant::now().as_millis());
    if report.get().permits_setup() {
        defmt::info!("Setup: release GPIO 23, hold for 3 seconds, then release to confirm");
    }
    loop {
        let now = Instant::now().as_millis();
        if report.get().permits_setup() {
            if gate.expired(now) {
                gate = super::presence::PresenceGate::new(now);
            }
            if let Some(confirmation) = gate.observe(button.is_low(), now) {
                report.set(Report {
                    state: State::Initializing,
                    reason: Reason::None,
                });
                match entropy.seed_rng().await {
                    Ok(mut rng) => {
                        let result = coordinator.initialize(confirmation, &mut rng).await;
                        report.set(coordinator.report());
                        defmt::info!(
                            "Setup result: {} ({})",
                            coordinator.report().state.as_str(),
                            coordinator.report().reason.as_str()
                        );
                        if let Err(error) = result {
                            defmt::warn!(
                                "Setup operation returned {}; persisted status was rechecked",
                                error.reason().as_str()
                            );
                        }
                    }
                    Err(_) => {
                        let mut status = coordinator.report();
                        status.reason = Reason::EntropyUnavailable;
                        report.set(status);
                        defmt::warn!("TRNG unavailable; setup stopped without a fallback seed");
                    }
                }
                gate = super::presence::PresenceGate::new(Instant::now().as_millis());
            }
        }
        Timer::after_millis(10).await;
    }
}
