use super::{
    hardware_policy as policy,
    record::{BootKeyHash, Error},
};
use core::sync::atomic::{AtomicBool, Ordering};
use doohickey_crypto::secrets::{MasterKey, MasterKeyProvider};
use embassy_rp::otp;

static TAKEN: AtomicBool = AtomicBool::new(false);

/// Secure-world, core-0 OTP access. No operations happen at construction.
/// No Clone/Debug, no raw row API, and no automatic provisioning.
pub struct Otp {
    _not_send: core::marker::PhantomData<*mut ()>,
}

impl Otp {
    pub fn new() -> Result<Self, Error> {
        if embassy_rp::multicore::current_core() != embassy_rp::multicore::CoreId::Core0 {
            return Err(Error::WrongCore);
        }
        TAKEN
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::AlreadyTaken)?;
        Ok(Self {
            _not_send: core::marker::PhantomData,
        })
    }
    pub async fn read_master_key(&mut self) -> Result<MasterKey, Error> {
        policy::read_master(&mut HardwareRows).map(MasterKey::from_bytes)
    }
    pub async fn master_key_status(&mut self) -> Result<super::MasterStatus, Error> {
        policy::master_status(&mut HardwareRows)
    }
    pub async fn read_secure_boot_key_hash(&mut self) -> Result<BootKeyHash, Error> {
        policy::read_boot_hash(&mut HardwareRows)
    }
    /// Irreversible. Requires `otp-provisioning`. Refuses any nonblank page;
    /// does not replace partial writes. Follow with explicit seal_master_key.
    pub async fn provision_master_key(&mut self, key: &MasterKey) -> Result<(), Error> {
        if !cfg!(feature = "otp-provisioning") {
            return Err(Error::ProvisioningDisabled);
        }
        critical_section::with(|_| {
            policy::provision_master(&mut HardwareRows, key.provisioning_bytes())
        })
    }
    /// Permanently make master page secure-read-only, nonsecure-inaccessible,
    /// bootloader-inaccessible. Does not enable secure boot or disable debug.
    pub async fn seal_master_key(&mut self) -> Result<(), Error> {
        if !cfg!(feature = "otp-provisioning") {
            return Err(Error::ProvisioningDisabled);
        }
        critical_section::with(|_| policy::seal_master(&mut HardwareRows))
    }
    /// Write BOOTKEY0's public-key hash, with readback verification. This does
    /// NOT set KEY_VALID, SECURE_BOOT_ENABLE, revocation, debug, or boot flags.
    pub async fn provision_secure_boot_key_hash(
        &mut self,
        hash: &BootKeyHash,
    ) -> Result<(), Error> {
        if !cfg!(feature = "otp-provisioning") {
            return Err(Error::ProvisioningDisabled);
        }
        critical_section::with(|_| policy::provision_boot_hash(&mut HardwareRows, hash))
    }
}

impl MasterKeyProvider for Otp {
    async fn load_master_key(&mut self) -> Result<MasterKey, doohickey_crypto::Error> {
        self.read_master_key()
            .await
            .map_err(|_| doohickey_crypto::Error::KeyUnavailable)
    }
}

impl Drop for Otp {
    fn drop(&mut self) {
        TAKEN.store(false, Ordering::Release);
    }
}

struct HardwareRows;

fn map_error(error: otp::Error) -> Error {
    match error {
        otp::Error::InvalidPermissions => Error::PermissionDenied,
        _ => Error::ReadFailed,
    }
}

impl policy::Rows for HardwareRows {
    fn raw(&mut self, row: usize) -> Result<u32, Error> {
        // Preflight permissions so ordinary access denials can return an error.
        // Guarded aliases additionally fail-stop on faults/transients; they can
        // raise a hardware bus fault rather than returning Err.
        otp::read_raw_word(row).map_err(map_error)?;
        // SAFETY: read_raw_word validated the index; raw alias has one u32 per
        // row. The guarded address is fixed by the RP2350 memory map.
        Ok(unsafe { (0x4013_c000 as *const u32).add(row).read_volatile() })
    }
    fn ecc(&mut self, row: usize) -> Result<u16, Error> {
        self.raw(row & !1)?;
        self.raw((row & !1) + 1)?;
        // SAFETY: indices checked above. A guarded u32 read validates both
        // neighboring 16-bit ECC rows. Records start/end on whole row pairs.
        let pair = unsafe { (0x4013_8000 as *const u32).add(row / 2).read_volatile() };
        Ok(if row & 1 == 0 {
            pair as u16
        } else {
            (pair >> 16) as u16
        })
    }
    fn write_ecc(&mut self, row: usize, value: u16) -> Result<(), Error> {
        #[cfg(feature = "otp-provisioning")]
        {
            if !(policy::MASTER_ROW..policy::MASTER_ROW + super::record::RECORD_SIZE / 2)
                .contains(&row)
                && !(policy::BOOT_HASH_ROW..policy::BOOT_HASH_ROW + 16).contains(&row)
            {
                return Err(Error::PermissionDenied);
            }
            let mut word = zeroize::Zeroizing::new([value]);
            // SAFETY: fixed allowed rows, aligned u16 RAM buffer, write+ECC
            // flags per ROM API. Called under a critical section on core 0.
            let result = unsafe {
                embassy_rp::rom_data::otp_access(
                    word.as_mut_ptr().cast(),
                    2,
                    row as u32 | 0x0003_0000,
                )
            };
            match result {
                0 => Ok(()),
                -4 => Err(Error::PermissionDenied),
                -18 => Err(Error::AlreadyProvisioned),
                _ => Err(Error::WriteFailed),
            }
        }
        #[cfg(not(feature = "otp-provisioning"))]
        {
            let _ = (row, value);
            Err(Error::ProvisioningDisabled)
        }
    }
    fn write_raw(&mut self, row: usize, value: u32) -> Result<(), Error> {
        #[cfg(feature = "otp-provisioning")]
        {
            if row != policy::MASTER_LOCK1 || value != policy::SEALED_LOCK {
                return Err(Error::PermissionDenied);
            }
            let mut word = [value];
            // SAFETY: fixed master-page lock value, aligned u32 RAM buffer,
            // with a critical section held on core 0.
            let result = unsafe {
                embassy_rp::rom_data::otp_access(
                    word.as_mut_ptr().cast(),
                    4,
                    row as u32 | 0x0001_0000,
                )
            };
            match result {
                0 => Ok(()),
                -4 => Err(Error::PermissionDenied),
                -18 => Err(Error::AlreadyProvisioned),
                _ => Err(Error::WriteFailed),
            }
        }
        #[cfg(not(feature = "otp-provisioning"))]
        {
            let _ = (row, value);
            Err(Error::ProvisioningDisabled)
        }
    }
}
