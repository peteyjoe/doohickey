//! Public serial information handler. No credential state or root-key access.
use core::fmt::{self, Write};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    AuthenticationUnavailable,
    OutputTooSmall,
}

/// Replace with a session-aware Noise adapter once secure pairing exists.
/// Parse application commands only after authenticated decryption in that mode.
pub trait Handler {
    fn handle(&mut self, frame: &[u8], response: &mut [u8]) -> Result<usize, Error>;
    fn disconnected(&mut self);
}

pub struct Information {
    pub flash_size: usize,
    pub insecure_test_otp: bool,
    pub initialization: crate::init::Report,
}

/// Both futures run on core 0. This Cell is never accessed by USB interrupts.
pub struct LiveInformation<'a> {
    pub flash_size: usize,
    pub insecure_test_otp: bool,
    pub initialization: &'a core::cell::Cell<crate::init::Report>,
}
impl Handler for LiveInformation<'_> {
    fn handle(&mut self, frame: &[u8], response: &mut [u8]) -> Result<usize, Error> {
        Information {
            flash_size: self.flash_size,
            insecure_test_otp: self.insecure_test_otp,
            initialization: self.initialization.get(),
        }
        .handle(frame, response)
    }
    fn disconnected(&mut self) {}
}

struct Buffer<'a> {
    bytes: &'a mut [u8],
    len: usize,
}
impl Write for Buffer<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        if end > self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}
impl Handler for Information {
    fn handle(&mut self, frame: &[u8], response: &mut [u8]) -> Result<usize, Error> {
        response.zeroize();
        if frame != b"INFO" {
            return Err(Error::AuthenticationUnavailable);
        }
        let mut buffer = Buffer {
            bytes: response,
            len: 0,
        };
        let result = write!(
            buffer,
            "{{\"product\":\"DOOHICKEY\",\"firmware\":\"{}\",\"flash_bytes\":{},\"ctap_ready\":false,\"authentication_ready\":false,\"insecure_test_otp\":{},\"initialization\":\"{}\",\"initialization_reason\":\"{}\"}}",
            env!("CARGO_PKG_VERSION"),
            self.flash_size,
            self.insecure_test_otp,
            self.initialization.state.as_str(),
            self.initialization.reason.as_str()
        );
        match result {
            Ok(()) => Ok(buffer.len),
            Err(_) => {
                buffer.bytes.zeroize();
                Err(Error::OutputTooSmall)
            }
        }
    }
    fn disconnected(&mut self) {}
}
