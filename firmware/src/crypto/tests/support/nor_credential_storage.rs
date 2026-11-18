use embedded_storage_async::nor_flash::{
    ErrorType, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
};
use sequential_storage::{
    cache::{Cache, Uncached},
    map::{MapConfig, MapStorage},
};
use std::{cell::RefCell, rc::Rc};
pub const MAX_VALUE_SIZE: usize = 1024;
#[derive(Clone, Copy, Debug)]
pub struct FlashError;
impl NorFlashError for FlashError {
    fn kind(&self) -> NorFlashErrorKind {
        NorFlashErrorKind::Other
    }
}
#[derive(Clone)]
pub struct Image(pub Rc<RefCell<Memory>>);
pub struct Memory {
    pub bytes: Vec<u8>,
    pub remaining: Option<usize>,
    pub mutations: usize,
}
impl Default for Image {
    fn default() -> Self {
        Self(Rc::new(RefCell::new(Memory {
            bytes: vec![255; 16384],
            remaining: None,
            mutations: 0,
        })))
    }
}
struct Flash(Image);
impl ErrorType for Flash {
    type Error = FlashError;
}
impl ReadNorFlash for Flash {
    const READ_SIZE: usize = 4;
    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), FlashError> {
        assert!((offset as usize).is_multiple_of(4) && bytes.len().is_multiple_of(4));
        bytes.copy_from_slice(
            &self.0.0.borrow().bytes[offset as usize..offset as usize + bytes.len()],
        );
        Ok(())
    }
    fn capacity(&self) -> usize {
        16384
    }
}
fn mutate(m: &mut Memory) -> Result<(), FlashError> {
    if let Some(remaining) = m.remaining.as_mut() {
        if *remaining == 0 {
            return Err(FlashError);
        }
        *remaining -= 1;
    }
    m.mutations += 1;
    Ok(())
}
impl NorFlash for Flash {
    const WRITE_SIZE: usize = 1;
    const ERASE_SIZE: usize = 4096;
    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), FlashError> {
        let mut m = self.0.0.borrow_mut();
        for (i, byte) in bytes.iter().enumerate() {
            mutate(&mut m)?;
            let target = &mut m.bytes[offset as usize + i];
            assert_eq!(*target & byte, *byte);
            *target &= byte;
        }
        Ok(())
    }
    async fn erase(&mut self, from: u32, to: u32) -> Result<(), FlashError> {
        let mut m = self.0.0.borrow_mut();
        for offset in from..to {
            mutate(&mut m)?;
            m.bytes[offset as usize] = 255;
        }
        Ok(())
    }
}
#[derive(Debug)]
pub enum Error {
    Store(sequential_storage::Error<FlashError>),
    Buffer,
}
impl Error {
    pub fn is_full(&self) -> bool {
        matches!(self, Self::Store(sequential_storage::Error::FullStorage))
    }
}
impl From<sequential_storage::Error<FlashError>> for Error {
    fn from(e: sequential_storage::Error<FlashError>) -> Self {
        Self::Store(e)
    }
}
type Map = MapStorage<u32, Flash, Cache<Uncached, Uncached, Uncached, u32>>;
pub struct Storage<'d> {
    map: Map,
    buffer: [u8; 1028],
    _lifetime: core::marker::PhantomData<&'d ()>,
}
impl Storage<'_> {
    pub fn open(image: Image) -> Self {
        Self {
            map: MapStorage::new(
                Flash(image),
                MapConfig::new(0..16384),
                Cache::new_uncached(),
            ),
            buffer: [0; 1028],
            _lifetime: core::marker::PhantomData,
        }
    }
    pub async fn read(&mut self, key: u32, out: &mut [u8]) -> Result<Option<usize>, Error> {
        let Some(value) = self.map.fetch_item::<&[u8]>(&mut self.buffer, &key).await? else {
            return Ok(None);
        };
        if out.len() < value.len() {
            return Err(Error::Buffer);
        }
        out[..value.len()].copy_from_slice(value);
        Ok(Some(value.len()))
    }
    pub async fn store(&mut self, key: u32, value: &[u8]) -> Result<(), Error> {
        self.map.store_item(&mut self.buffer, &key, &value).await?;
        Ok(())
    }
}
#[path = "../../../storage/credentials.rs"]
pub mod credentials;
#[path = "../../../storage/encrypted.rs"]
pub mod encrypted;
