//! Hardware policy, independent of MMIO so interrupted writes can be tested.
use super::record::{self, BootKeyHash, Error, RECORD_SIZE};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(super) const MASTER_ROW: usize = 0x400; // application page 16, 64 rows
pub(super) const MASTER_LOCK0: usize = 0xfa0;
pub(super) const MASTER_LOCK1: usize = 0xfa1;
pub(super) const BOOT_HASH_ROW: usize = 0x80; // BOOTKEY0_0, 16 ECC rows
const BOOT_FLAGS1: usize = 0x4b; // three redundant words, not modified here
// S=read-only, NS=inaccessible, bootloader=inaccessible, all redundant copies.
pub(super) const SEALED_LOCK: u32 = 0x3d3d3d;

pub(super) trait Rows {
    fn raw(&mut self, row: usize) -> Result<u32, Error>;
    fn ecc(&mut self, row: usize) -> Result<u16, Error>;
    fn write_ecc(&mut self, row: usize, value: u16) -> Result<(), Error>;
    fn write_raw(&mut self, row: usize, value: u32) -> Result<(), Error>;
}

fn blank(rows: &mut impl Rows, start: usize, count: usize) -> Result<bool, Error> {
    for row in start..start + count {
        if rows.raw(row)? != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn master_record(rows: &mut impl Rows) -> Result<Zeroizing<[u8; 32]>, Error> {
    if blank(rows, MASTER_ROW, 64)? {
        return Err(Error::Unprovisioned);
    }
    // Never guarded-read a partially programmed pair or accept incomplete data.
    for row in MASTER_ROW + 36..MASTER_ROW + 38 {
        if rows.raw(row)? == 0 {
            return Err(Error::IncompleteProvisioning);
        }
    }
    let mut record = Zeroizing::new([0; RECORD_SIZE]);
    for (index, chunk) in record.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        chunk.copy_from_slice(&rows.ecc(MASTER_ROW + index)?.to_le_bytes());
    }
    record::decode(&record[..])
}

pub(super) fn read_master(rows: &mut impl Rows) -> Result<Zeroizing<[u8; 32]>, Error> {
    // Fail before touching secret data when the hard-lock policy is absent.
    if blank(rows, MASTER_ROW, 64)? {
        return Err(Error::Unprovisioned);
    }
    if rows.raw(MASTER_LOCK1)? != SEALED_LOCK {
        return Err(Error::NotSealed);
    }
    master_record(rows)
}

pub(super) fn master_status(rows: &mut impl Rows) -> Result<record::MasterStatus, Error> {
    let lock0 = rows.raw(MASTER_LOCK0)?;
    let lock1 = rows.raw(MASTER_LOCK1)?;
    if lock0 != 0 || (lock1 != 0 && lock1 != SEALED_LOCK) {
        return Err(Error::PermissionDenied);
    }
    if blank(rows, MASTER_ROW, 64)? {
        return if lock1 == 0 {
            Ok(record::MasterStatus::Blank)
        } else {
            Err(Error::Corrupt)
        };
    }
    // A full record is required before offering an explicitly authorized seal
    // resume. No unsealed or partially programmed secret is returned to callers.
    let _key = master_record(rows)?;
    Ok(if lock1 == SEALED_LOCK {
        record::MasterStatus::Sealed
    } else {
        record::MasterStatus::Unsealed
    })
}

pub(super) fn provision_master(rows: &mut impl Rows, value: &[u8; 32]) -> Result<(), Error> {
    let record = record::encode(value)?;
    if rows.raw(MASTER_LOCK0)? != 0 || rows.raw(MASTER_LOCK1)? != 0 {
        return Err(Error::PermissionDenied);
    }
    if !blank(rows, MASTER_ROW, 64)? {
        return Err(Error::AlreadyProvisioned);
    }
    // The last two rows form the commit marker; program them last. Never retry
    // a partial record by setting extra bits or substituting a different key.
    for (index, chunk) in record.as_chunks::<2>().0.iter().enumerate() {
        rows.write_ecc(MASTER_ROW + index, u16::from_le_bytes([chunk[0], chunk[1]]))?;
    }
    let recovered = master_record(rows)?;
    if !bool::from(recovered[..].ct_eq(value)) {
        return Err(Error::Corrupt);
    }
    Ok(())
}

pub(super) fn seal_master(rows: &mut impl Rows) -> Result<(), Error> {
    // Verify a complete record before any irreversible permission change.
    let _key = master_record(rows)?;
    if rows.raw(MASTER_LOCK0)? != 0 {
        return Err(Error::PermissionDenied);
    }
    let lock = rows.raw(MASTER_LOCK1)?;
    if lock == SEALED_LOCK {
        return Ok(());
    }
    if lock != 0 {
        return Err(Error::PermissionDenied);
    }
    rows.write_raw(MASTER_LOCK1, SEALED_LOCK)?;
    if rows.raw(MASTER_LOCK1)? != SEALED_LOCK {
        return Err(Error::WriteFailed);
    }
    Ok(())
}

pub(super) fn read_boot_hash(rows: &mut impl Rows) -> Result<BootKeyHash, Error> {
    if blank(rows, BOOT_HASH_ROW, 16)? {
        return Err(Error::Unprovisioned);
    }
    let mut value = [0; 32];
    for (index, chunk) in value.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        chunk.copy_from_slice(&rows.ecc(BOOT_HASH_ROW + index)?.to_le_bytes());
    }
    BootKeyHash::from_bytes(value)
}

pub(super) fn provision_boot_hash(rows: &mut impl Rows, hash: &BootKeyHash) -> Result<(), Error> {
    // Reject valid/revoked key slots; only explicit external provisioning tools
    // may activate/revoke keys or enable secure boot. Never change those flags.
    let a = rows.raw(BOOT_FLAGS1)?;
    let b = rows.raw(BOOT_FLAGS1 + 1)?;
    let c = rows.raw(BOOT_FLAGS1 + 2)?;
    let flags = (a & b) | (a & c) | (b & c);
    if flags & 0x101 != 0 || !blank(rows, BOOT_HASH_ROW, 16)? {
        return Err(Error::AlreadyProvisioned);
    }
    for (index, chunk) in hash.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        rows.write_ecc(
            BOOT_HASH_ROW + index,
            u16::from_le_bytes([chunk[0], chunk[1]]),
        )?;
    }
    if read_boot_hash(rows)? != *hash {
        return Err(Error::Corrupt);
    }
    Ok(())
}
