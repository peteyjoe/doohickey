//! Public serial information handler. No credential state or root-key access.
use core::fmt::{self, Write};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    AuthenticationUnavailable,
    OutputTooSmall,
}

/// Public diagnostics plus an asynchronous single-owner serial adapter.
/// Authentication and encrypted command parsing belong to serial_service.
#[allow(async_fn_in_trait)]
pub trait Handler {
    #[cfg(target_os = "none")]
    async fn handle_async(
        &mut self,
        sessions: &super::session::SessionState,
        frame: &[u8],
        response: &mut [u8],
    ) -> Result<usize, Error> {
        let _ = sessions;
        self.handle(frame, response)
    }
    fn handle(&mut self, frame: &[u8], response: &mut [u8]) -> Result<usize, Error>;
    fn disconnected(&mut self);
}

pub struct Information {
    pub ctap_ready: bool,
    pub flash_size: usize,
    pub insecure_test_otp: bool,
    pub initialization: crate::init::Report,
}

/// Both futures run on core 0. This Cell is never accessed by USB interrupts.
pub struct LiveInformation<'a> {
    pub ctap_ready: &'a core::cell::Cell<bool>,
    pub flash_size: usize,
    pub insecure_test_otp: bool,
    pub initialization: &'a core::cell::Cell<crate::init::Report>,
}
impl Handler for LiveInformation<'_> {
    fn handle(&mut self, frame: &[u8], response: &mut [u8]) -> Result<usize, Error> {
        Information {
            ctap_ready: self.ctap_ready.get(),
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
            "{{\"product\":\"DOOHICKEY\",\"firmware\":\"{}\",\"flash_bytes\":{},\"ctap_ready\":{},\"authentication_ready\":false,\"insecure_test_otp\":{},\"initialization\":\"{}\",\"initialization_reason\":\"{}\"}}",
            env!("CARGO_PKG_VERSION"),
            self.flash_size,
            self.ctap_ready,
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

/// Serial commands are copied to the same single storage owner as CTAP.
#[cfg(target_os = "none")]
pub struct SerialAdapter<'a> {
    pub information: LiveInformation<'a>,
    pub exchange: &'a crate::ctap::exchange::Exchange,
}
#[cfg(target_os = "none")]
impl Handler for SerialAdapter<'_> {
    fn handle(&mut self, frame: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let n = self.information.handle(frame, out)?;
        let before = b"\"authentication_ready\":false";
        let after = b"\"authentication_ready\":true";
        if self.information.ctap_ready.get()
            && let Some(i) = out[..n].windows(before.len()).position(|w| w == before)
        {
            out.copy_within(i + before.len()..n, i + after.len());
            out[i..i + after.len()].copy_from_slice(after);
            return Ok(n - before.len() + after.len());
        }
        Ok(n)
    }
    async fn handle_async(
        &mut self,
        sessions: &super::session::SessionState,
        frame: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if frame == b"INFO" {
            return self.handle(frame, out);
        }
        let epoch = sessions.serial_epoch();
        self.exchange
            .start(frame)
            .map_err(|_| Error::AuthenticationUnavailable)?;
        loop {
            if sessions.serial_epoch() != epoch || !sessions.configured() {
                self.exchange.cancel();
            }
            if let Some(result) = self.exchange.result(out) {
                return result.map_err(|_| Error::AuthenticationUnavailable);
            }
            embassy_time::Timer::after_millis(5).await;
        }
    }
    fn disconnected(&mut self) {
        self.exchange.cancel();
    }
}
