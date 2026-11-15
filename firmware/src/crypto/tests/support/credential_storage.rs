//! Raw byte-store substitute. Production encryption and repository code remain
//! unchanged; failures model an atomic old/new value and lost acknowledgement.
pub const MAX_VALUE_SIZE: usize = 1024;
#[derive(Debug)]
pub enum Error {
    Read,
    Write,
    Full,
    Buffer,
}
impl Error {
    pub fn is_full(&self) -> bool {
        matches!(self, Self::Full)
    }
}
#[derive(Default)]
pub struct Storage<'d> {
    pub values: std::collections::BTreeMap<u32, Vec<u8>>,
    pub fail_read: bool,
    pub fail_before: bool,
    pub fail_after: bool,
    pub full: bool,
    pub fail_at: Option<usize>,
    pub reads: usize,
    pub writes: usize,
    pub _lifetime: core::marker::PhantomData<&'d ()>,
}
impl Storage<'_> {
    pub async fn read(&mut self, key: u32, out: &mut [u8]) -> Result<Option<usize>, Error> {
        self.reads += 1;
        if self.fail_read {
            return Err(Error::Read);
        }
        let Some(value) = self.values.get(&key) else {
            return Ok(None);
        };
        if value.len() > out.len() {
            return Err(Error::Buffer);
        }
        out[..value.len()].copy_from_slice(value);
        Ok(Some(value.len()))
    }
    pub async fn store(&mut self, key: u32, value: &[u8]) -> Result<(), Error> {
        self.writes += 1;
        if self.full {
            return Err(Error::Full);
        }
        if self.fail_before && self.fail_at.is_none_or(|at| at == self.writes) {
            return Err(Error::Write);
        }
        self.values.insert(key, value.to_vec());
        if self.fail_after && self.fail_at.is_none_or(|at| at == self.writes) {
            return Err(Error::Write);
        }
        Ok(())
    }
}
#[path = "../../../storage/credentials.rs"]
pub mod credentials;
#[path = "../../../storage/encrypted.rs"]
pub mod encrypted;
