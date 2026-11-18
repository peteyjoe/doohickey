//! Serial byte-stream framing, independent of USB packet boundaries.
//! Same u16 big-endian length envelope used by the serial crypto layer.
use zeroize::Zeroize;

pub const MAX_FRAME_SIZE: usize = 1040;
pub const FRAME_TIMEOUT_MS: u64 = 2000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidLength,
    Timeout,
    SessionInvalid,
}

pub struct Decoder {
    bytes: [u8; MAX_FRAME_SIZE],
    header: [u8; 2],
    header_len: usize,
    length: usize,
    received: usize,
    deadline: Option<u64>,
    invalid: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
impl Decoder {
    pub const fn new() -> Self {
        Self {
            bytes: [0; MAX_FRAME_SIZE],
            header: [0; 2],
            header_len: 0,
            length: 0,
            received: 0,
            deadline: None,
            invalid: false,
        }
    }
    pub fn reset(&mut self) {
        self.bytes.zeroize();
        self.header.zeroize();
        self.header_len = 0;
        self.length = 0;
        self.received = 0;
        self.deadline = None;
        self.invalid = false;
    }
    fn fail(&mut self, error: Error) -> Error {
        self.reset();
        self.invalid = true;
        error
    }
    /// A damaged frame locks the session until an explicit connection reset.
    /// Do not guess where the next encrypted frame starts after an error.
    pub fn check_timeout(&mut self, now_ms: u64) -> Result<(), Error> {
        if self.invalid {
            return Err(Error::SessionInvalid);
        }
        if self.deadline.is_some_and(|deadline| now_ms >= deadline) {
            return Err(self.fail(Error::Timeout));
        }
        Ok(())
    }
    pub fn push(&mut self, byte: u8, now_ms: u64) -> Result<Option<&[u8]>, Error> {
        self.check_timeout(now_ms)?;
        if self.deadline.is_none() {
            self.bytes.zeroize();
            self.deadline = Some(now_ms.saturating_add(FRAME_TIMEOUT_MS));
        }
        if self.header_len < 2 {
            self.header[self.header_len] = byte;
            self.header_len += 1;
            if self.header_len == 2 {
                self.length = u16::from_be_bytes(self.header) as usize;
                if self.length == 0 || self.length > MAX_FRAME_SIZE {
                    return Err(self.fail(Error::InvalidLength));
                }
            }
            return Ok(None);
        }
        self.bytes[self.received] = byte;
        self.received += 1;
        if self.received == self.length {
            let length = self.length;
            self.header_len = 0;
            self.received = 0;
            self.length = 0;
            self.deadline = None;
            Ok(Some(&self.bytes[..length]))
        } else {
            Ok(None)
        }
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
