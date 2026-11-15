//! Immediate read-only CTAP discovery adapter. Future stateful handlers must
//! own copied request bytes; this adapter retains only a pending-command bit.
use super::ctaphid::{Backend, Completion};
use crate::ctap::{
    self, Request, Status,
    codec::{self, Scratch},
};
use zeroize::Zeroize;

#[derive(Default)]
pub struct DiscoveryBackend {
    pending: bool,
}
impl Backend for DiscoveryBackend {
    fn start(&mut self, _channel: u32, request: &[u8]) -> Result<(), Status> {
        if self.pending {
            return Err(Status::NotAllowed);
        }
        let mut scratch = Scratch::new();
        match codec::decode(request, &mut scratch)? {
            Request::GetInfo => {
                self.pending = true;
                Ok(())
            }
            _ => Err(Status::InvalidCommand),
        }
    }
    fn poll(&mut self, output: &mut [u8]) -> Completion {
        output.zeroize();
        if !core::mem::take(&mut self.pending) {
            return Completion::Ready(Err(Status::NotAllowed));
        }
        Completion::Ready(ctap::info::encode(output))
    }
    fn cancel(&mut self) { /* GetInfo has no user-presence or persistent operation to cancel. */
    }
    fn resynchronize(&mut self, _channel: u32) {
        self.pending = false;
    }
    fn disconnected(&mut self) {
        self.pending = false;
    }
}

/// Own copied bytes until the asynchronous single storage owner has finished.
/// Cancellation/resync/disconnect signal it; they never drop its I/O future.
pub struct AuthenticatorBackend<'a>(pub &'a crate::ctap::exchange::Exchange);
impl Backend for AuthenticatorBackend<'_> {
    fn start(&mut self, channel: u32, request: &[u8]) -> Result<(), Status> {
        self.0.channel(channel);
        self.0.start(request)
    }
    fn poll(&mut self, output: &mut [u8]) -> Completion {
        match self.0.result(output) {
            Some(result) => Completion::Ready(result),
            None => Completion::Pending(if self.0.waiting_for_presence() {
                super::ctaphid::Progress::UserPresence
            } else {
                super::ctaphid::Progress::Processing
            }),
        }
    }
    fn cancel(&mut self) {
        self.0.cancel();
    }
    fn resynchronize(&mut self, _channel: u32) {
        self.0.cancel();
    }
    fn disconnected(&mut self) {
        self.0.cancel();
    }
}
