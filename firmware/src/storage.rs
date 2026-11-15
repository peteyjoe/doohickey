//! Persistent key-value storage after the fixed firmware region.
//!
//! Import with `use crate::storage::Storage`. Create one instance on core 0
//! using `Storage::new(peripherals.FLASH, peripherals.DMA_CH0)`, then move it
//! into the task that owns storage. Other tasks should send requests to that
//! task, or share the instance through an async mutex. Await operations to
//! completion rather than cancelling them with a timeout/select.
//!
//! Values are raw bytes, not encrypted. Construction does not format flash;
//! existing records survive resets. A full-chip erase removes all records.
//! `build.rs` generates the linker layout and constants below together.
//! Default builds use 4 MiB flash; `flash-16mb` selects 16 MiB flash.
//! Use `EncryptedStorage` for authenticated encryption of application values.

#[path = "storage/encrypted.rs"]
pub mod encrypted;
pub use encrypted::{EncryptedStorage, RecordKind};
#[path = "storage/backup.rs"]
pub mod backup;
#[path = "storage/credentials.rs"]
pub mod credentials;

#[path = "storage/metadata.rs"]
mod metadata;
pub use metadata::{MAGIC, Metadata, VERSION};

use embassy_rp::flash::{Async, Error as FlashError, Flash};
use embassy_rp::peripherals::{DMA_CH0, FLASH};
use embassy_rp::{Peri, bind_interrupts};
use sequential_storage::cache::{Cache, Uncached};
use sequential_storage::map::{MapConfig, MapStorage};
#[cfg(feature = "insecure-test-otp")]
use zeroize::Zeroize;

// STORAGE_START is relative to flash, not an absolute CPU/XIP address.
include!(concat!(env!("OUT_DIR"), "/flash_layout.rs"));
pub const MAX_VALUE_SIZE: usize = 1024;
/// Reserved for the magic and firmware version; application keys start at 1.
pub const METADATA_KEY: u32 = 0;
/// Reserved for flash-backed OTP tests in every build, preventing collisions.
pub(crate) const OTP_TEST_KEYS: core::ops::RangeInclusive<u32> = 0xffff_ff00..=0xffff_ff02;
/// Coordinator-owned initialization, lifecycle watermark and transaction.
pub(crate) const INITIALIZATION_KEYS: core::ops::RangeInclusive<u32> = 0xffff_fd00..=0xffff_fe04;

const _: () = assert!(metadata::CURRENT_RECORD.len() <= MAX_VALUE_SIZE);

type FlashDriver<'d> = Flash<'d, FLASH, Async, FLASH_SIZE>;
type StorageCache = Cache<Uncached, Uncached, Uncached, u32>;

bind_interrupts!(struct FlashIrqs {
    DMA_IRQ_0 => embassy_rp::dma::InterruptHandler<DMA_CH0>;
});

#[derive(Debug)]
pub enum Error {
    /// Application reads/writes cannot access metadata or OTP test keys.
    ReservedKey,
    /// The partition contains data but no metadata. Initialization did not
    /// create metadata or format the partition; explicit migration is needed.
    MissingMetadata,
    /// The metadata has an incorrect magic value or invalid version encoding.
    InvalidMetadata,
    /// Raw flash access while checking whether a partition is erased.
    Flash(FlashError),
    /// A value exceeds MAX_VALUE_SIZE; nothing was written.
    ValueTooLarge,
    /// The caller's output buffer is too small; it was not modified.
    BufferTooSmall { required: usize },
    /// Flash access, serialization, capacity, or corruption error.
    Storage(sequential_storage::Error<FlashError>),
}

impl From<sequential_storage::Error<FlashError>> for Error {
    fn from(error: sequential_storage::Error<FlashError>) -> Self {
        Self::Storage(error)
    }
}
impl Error {
    pub fn is_full(&self) -> bool {
        matches!(self, Self::Storage(sequential_storage::Error::FullStorage))
    }
}

/// Heap-free storage using u32 keys and byte values of up to 1 KiB.
///
/// Storing an existing key replaces its logical value. Keep each key's byte
/// encoding consistent across firmware versions (e.g. use little-endian integers
/// or an explicitly versioned serialization format).
pub struct Storage<'d> {
    map: MapStorage<u32, FlashDriver<'d>, StorageCache>,
    // Four bytes for the key plus the maximum value: a multiple of the flash
    // read size. The flash driver handles buffers without aligned addresses.
    buffer: [u8; MAX_VALUE_SIZE + size_of::<u32>()],
}

impl<'d> Storage<'d> {
    /// Idempotent reset cleanup. Keep metadata, coordinator transaction and
    /// flash-emulated trust keys. Never erase the partition or hardware OTP.
    pub(crate) async fn clear_application(&mut self) -> Result<(), Error> {
        loop {
            let mut items = self.map.fetch_all_items(&mut self.buffer).await?;
            let mut selected = None;
            while let Some((key, _)) = items.next::<&[u8]>(&mut self.buffer).await? {
                if key != METADATA_KEY
                    && !INITIALIZATION_KEYS.contains(&key)
                    && !OTP_TEST_KEYS.contains(&key)
                {
                    selected = Some(key);
                    break;
                }
            }
            let Some(key) = selected else { break };
            self.map.remove_item(&mut self.buffer, &key).await?;
        }
        self.buffer.fill(0);
        Ok(())
    }
    pub(crate) async fn remove_initialization(&mut self, key: u32) -> Result<(), Error> {
        if !INITIALIZATION_KEYS.contains(&key) {
            return Err(Error::ReservedKey);
        }
        self.map.remove_item(&mut self.buffer, &key).await?;
        self.buffer.fill(0);
        Ok(())
    }
    /// Take ownership of flash and DMA channel 0. No reads, writes, or erases
    /// happen until a method is awaited. The first store can use erased flash
    /// without a separate format step.
    pub fn new(flash: Peri<'d, FLASH>, dma: Peri<'d, DMA_CH0>) -> Self {
        let flash = Flash::new(flash, dma, FlashIrqs);
        let config = const { MapConfig::new(STORAGE_START..FLASH_SIZE as u32) };
        Self {
            map: MapStorage::new(flash, config, Cache::new_uncached()),
            buffer: [0; MAX_VALUE_SIZE + size_of::<u32>()],
        }
    }

    /// Create metadata only on a completely erased partition. Existing valid
    /// metadata is retained, including its version after a firmware update.
    /// No format or version migration is performed automatically.
    ///
    /// Call before application reads/writes. Scanning an erased partition can
    /// take time, especially on the 16 MiB variant. Existing stores usually
    /// stop the erased check at the first non-0xFF block.
    pub async fn initialize_metadata(&mut self) -> Result<(), Error> {
        if self.is_erased().await? {
            self.write_metadata().await
        } else if self.metadata().await?.is_some() {
            Ok(())
        } else {
            Err(Error::MissingMetadata)
        }
    }

    /// Inspect the entire selected storage partition without creating metadata
    /// or invoking the log's repair path. An absent key alone is not evidence
    /// of a new device. May scan 13 MiB on a blank 16 MiB device.
    pub async fn is_erased(&mut self) -> Result<bool, Error> {
        let result = async {
            let mut offset = STORAGE_START;
            while offset < FLASH_SIZE as u32 {
                self.map
                    .flash()
                    .read(offset, &mut self.buffer[..1024])
                    .await
                    .map_err(Error::Flash)?;
                if self.buffer[..1024].iter().any(|byte| *byte != 0xff) {
                    return Ok(false);
                }
                offset += 1024;
            }
            Ok(true)
        }
        .await;
        self.buffer.fill(0);
        result
    }

    /// Read metadata without changing its version. The returned fields borrow
    /// this instance's scratch buffer and are valid until the next operation.
    /// The underlying store may repair interrupted writes while reading.
    pub async fn metadata(&mut self) -> Result<Option<Metadata<'_>>, Error> {
        let Some(bytes) = self
            .map
            .fetch_item::<&[u8]>(&mut self.buffer, &METADATA_KEY)
            .await?
        else {
            return Ok(None);
        };
        metadata::decode(bytes)
            .map(Some)
            .ok_or(Error::InvalidMetadata)
    }

    /// Explicitly record the current firmware version after the caller has
    /// verified compatibility or completed migration. Never call this merely
    /// to hide a version mismatch. Repeated calls at the same version do not
    /// write flash.
    pub async fn update_metadata_version(&mut self) -> Result<(), Error> {
        let metadata = self.metadata().await?.ok_or(Error::MissingMetadata)?;
        if metadata.version == VERSION {
            return Ok(());
        }
        self.write_metadata().await
    }

    async fn write_metadata(&mut self) -> Result<(), Error> {
        self.map
            .store_item(&mut self.buffer, &METADATA_KEY, &metadata::CURRENT_RECORD)
            .await?;
        Ok(())
    }

    /// Read the latest value into `output`, returning its length.
    ///
    /// `None` means the key has never been stored. `Some(0)` is an existing
    /// empty value. Only `output[..length]` is modified on success.
    pub async fn read(&mut self, key: u32, output: &mut [u8]) -> Result<Option<usize>, Error> {
        if key == METADATA_KEY || OTP_TEST_KEYS.contains(&key) || INITIALIZATION_KEYS.contains(&key)
        {
            return Err(Error::ReservedKey);
        }
        self.read_entry(key, output).await
    }

    async fn read_entry(&mut self, key: u32, output: &mut [u8]) -> Result<Option<usize>, Error> {
        let Some(value) = self.map.fetch_item::<&[u8]>(&mut self.buffer, &key).await? else {
            return Ok(None);
        };
        if output.len() < value.len() {
            return Err(Error::BufferTooSmall {
                required: value.len(),
            });
        }
        output[..value.len()].copy_from_slice(value);
        Ok(Some(value.len()))
    }

    /// Persist a value, replacing any previous value stored under the key.
    ///
    /// Writes are append-based with wear leveling and CRC checks. This does
    /// not provide transactions spanning multiple keys, encryption, or secure
    /// deletion of historical values. Flash writes/erases briefly block the CPU
    /// even though the storage interface is async.
    pub async fn store(&mut self, key: u32, value: &[u8]) -> Result<(), Error> {
        if key == METADATA_KEY || OTP_TEST_KEYS.contains(&key) || INITIALIZATION_KEYS.contains(&key)
        {
            return Err(Error::ReservedKey);
        }
        self.store_entry(key, value).await
    }

    async fn store_entry(&mut self, key: u32, value: &[u8]) -> Result<(), Error> {
        if value.len() > MAX_VALUE_SIZE {
            return Err(Error::ValueTooLarge);
        }
        self.map.store_item(&mut self.buffer, &key, &value).await?;
        Ok(())
    }

    pub(crate) async fn read_initialization(
        &mut self,
        key: u32,
        output: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        if !INITIALIZATION_KEYS.contains(&key) {
            return Err(Error::ReservedKey);
        }
        if self.metadata().await?.is_none() {
            return Err(Error::MissingMetadata);
        }
        self.read_entry(key, output).await
    }
    pub(crate) async fn store_initialization(
        &mut self,
        key: u32,
        value: &[u8],
    ) -> Result<(), Error> {
        if !INITIALIZATION_KEYS.contains(&key) {
            return Err(Error::ReservedKey);
        }
        if self.metadata().await?.is_none() {
            return Err(Error::MissingMetadata);
        }
        self.store_entry(key, value).await
    }
    /// Conservative history scan: even an obsolete unrelated record blocks
    /// first-use/resume inference. Completed initialization does not need it.
    pub(crate) async fn contains_only_setup_data(&mut self) -> Result<bool, Error> {
        let result = async {
            let mut items = self.map.fetch_all_items(&mut self.buffer).await?;
            while let Some((key, _value)) = items.next::<&[u8]>(&mut self.buffer).await? {
                if key != METADATA_KEY
                    && !INITIALIZATION_KEYS.contains(&key)
                    && !(cfg!(feature = "insecure-test-otp") && OTP_TEST_KEYS.contains(&key))
                {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        .await;
        self.buffer.fill(0);
        result
    }

    #[cfg(feature = "insecure-test-otp")]
    pub(crate) async fn read_otp_test(
        &mut self,
        key: u32,
        output: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        if !OTP_TEST_KEYS.contains(&key) {
            return Err(Error::ReservedKey);
        }
        let result = async {
            if self.metadata().await?.is_none() {
                return Err(Error::MissingMetadata);
            }
            self.read_entry(key, output).await
        }
        .await;
        self.buffer.zeroize();
        result
    }

    #[cfg(feature = "insecure-test-otp")]
    pub(crate) async fn store_otp_test(&mut self, key: u32, value: &[u8]) -> Result<(), Error> {
        if !OTP_TEST_KEYS.contains(&key) {
            return Err(Error::ReservedKey);
        }
        let result = async {
            if self.metadata().await?.is_none() {
                return Err(Error::MissingMetadata);
            }
            self.store_entry(key, value).await
        }
        .await;
        self.buffer.zeroize();
        result
    }
}
