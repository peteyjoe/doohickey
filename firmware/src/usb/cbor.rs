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
