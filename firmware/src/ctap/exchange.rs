//! Single-core mailbox between the HID engine and the asynchronous storage
//! owner. RefCell borrows never span an await. No interrupt accesses this state.
use super::{Result, Status};
use core::cell::{Cell, RefCell};
use zeroize::Zeroize;
pub const CAPACITY: usize = super::cbor::MAX_MESSAGE_SIZE;
#[derive(Clone, Copy)]
enum State {
    Idle,
    Queued(usize),
    Working,
    Done(Result<usize>),
}
struct Inner {
    state: State,
    bytes: [u8; CAPACITY],
}
pub struct Exchange {
    inner: RefCell<Inner>,
    cancelled: Cell<bool>,
    presence: Cell<bool>,
    pub ready: Cell<bool>,
    pub epoch: Cell<u64>,
    channel: Cell<u32>,
}
impl Default for Exchange {
    fn default() -> Self {
        Self::new()
    }
}
impl Exchange {
    pub fn new() -> Self {
        Self {
            inner: RefCell::new(Inner {
                state: State::Idle,
                bytes: [0; CAPACITY],
            }),
            cancelled: Cell::new(false),
            presence: Cell::new(false),
            ready: Cell::new(false),
            epoch: Cell::new(0),
            channel: Cell::new(0),
        }
    }
    pub fn start(&self, input: &[u8]) -> Result<()> {
        let mut inner = self.inner.borrow_mut();
        if !matches!(inner.state, State::Idle) {
            return Err(Status::NotAllowed);
        }
        if input.is_empty() {
            return Err(Status::InvalidLength);
        }
        if input.len() > CAPACITY {
            return Err(Status::RequestTooLarge);
        }
        inner.bytes.zeroize();
        inner.bytes[..input.len()].copy_from_slice(input);
        inner.state = State::Queued(input.len());
        self.cancelled.set(false);
        self.presence.set(false);
        Ok(())
    }
    pub fn take(&self, output: &mut [u8; CAPACITY]) -> Option<usize> {
        let mut inner = self.inner.borrow_mut();
        let State::Queued(len) = inner.state else {
            return None;
        };
        output.zeroize();
        output[..len].copy_from_slice(&inner.bytes[..len]);
        inner.bytes.zeroize();
        inner.state = State::Working;
        Some(len)
    }
    pub fn complete(&self, result: Result<usize>, output: &[u8]) {
        let mut inner = self.inner.borrow_mut();
        assert!(matches!(inner.state, State::Working));
        inner.bytes.zeroize();
        let result = if self.cancelled() {
            Err(Status::KeepaliveCancel)
        } else {
            match result {
                Ok(n) if n < CAPACITY && n <= output.len() => {
                    inner.bytes[..n].copy_from_slice(&output[..n]);
                    Ok(n)
                }
                Ok(_) => Err(Status::Other),
                Err(error) => Err(error),
            }
        };
        self.presence.set(false);
        inner.state = State::Done(result);
    }
    pub fn result(&self, output: &mut [u8]) -> Option<Result<usize>> {
        output.zeroize();
        let mut inner = self.inner.borrow_mut();
        let State::Done(result) = inner.state else {
            return None;
        };
        let result = if self.cancelled() {
            Err(Status::KeepaliveCancel)
        } else {
            match result {
                Ok(n) if n <= output.len() => {
                    output[..n].copy_from_slice(&inner.bytes[..n]);
                    Ok(n)
                }
                Ok(_) => Err(Status::Other),
                Err(error) => Err(error),
            }
        };
        inner.bytes.zeroize();
        inner.state = State::Idle;
        Some(result)
    }
    pub fn channel(&self, channel: u32) {
        if self.channel.replace(channel) != channel {
            self.epoch.set(self.epoch.get().wrapping_add(1));
        }
    }
    pub fn cancel(&self) {
        self.epoch.set(self.epoch.get().wrapping_add(1));
        self.cancelled.set(true);
    }
    pub fn cancelled(&self) -> bool {
        self.cancelled.get()
    }
    pub fn waiting_for_presence(&self) -> bool {
        self.presence.get()
    }
    pub fn set_presence(&self, value: bool) {
        self.presence.set(value);
    }
}
