use super::{Backend, Error, Partition, RootStatus};
use crate::{otp, storage};
use doohickey_crypto::secrets::MasterKey;
use embassy_time::Instant;

pub struct DeviceBackend<'d> {
    storage: storage::Storage<'d>,
    erased: bool,
}
impl<'d> DeviceBackend<'d> {
    pub(crate) fn storage(&mut self) -> &mut storage::Storage<'d> {
        &mut self.storage
    }
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
    async fn restore_record(&mut self, key: u32, value: &[u8]) -> Result<(), Error> {
        if !storage::backup::allowed(key) {
            return Err(Error::InvalidInitialization);
        }
        self.storage
            .store(key, value)
            .await
            .map_err(storage_error)?;
        let mut check = zeroize::Zeroizing::new([0; 1024]);
        if self
            .storage
            .read(key, &mut check[..])
            .await
            .map_err(storage_error)?
            != Some(value.len())
            || check[..value.len()] != *value
        {
            return Err(Error::VerificationFailed);
        }
        Ok(())
    }
    fn geometry(&self) -> super::lifecycle::Geometry {
        super::lifecycle::Geometry {
            storage_start: storage::STORAGE_START,
            flash_size: storage::FLASH_SIZE as u32,
        }
    }
    async fn clear_application(&mut self) -> Result<(), Error> {
        self.storage
            .clear_application()
            .await
            .map_err(storage_error)
    }
    async fn remove(&mut self, key: u32) -> Result<(), Error> {
        self.storage
            .remove_initialization(key)
            .await
            .map_err(storage_error)
    }
    async fn update_metadata_version(&mut self) -> Result<(), Error> {
        self.storage
            .update_metadata_version()
            .await
            .map_err(storage_error)
    }
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
            match super::lifecycle::upgrade(metadata.version, storage::VERSION) {
                super::lifecycle::Upgrade::Current => Partition::Compatible,
                super::lifecycle::Upgrade::Migrate => Partition::Migrate,
                super::lifecycle::Upgrade::DowngradeBlocked => Partition::DowngradeBlocked,
                super::lifecycle::Upgrade::Unsupported => Partition::DifferentVersion,
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
