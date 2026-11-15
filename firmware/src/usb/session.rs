//! Connection generations shared by the USB control task and endpoint tasks.
use core::{
    future::{Future, poll_fn},
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
    task::Poll,
};

pub(crate) enum Interface {
    Hid,
    Serial,
}
pub struct SessionState {
    epoch: AtomicU32,
    serial_epoch: AtomicU32,
    configured: AtomicBool,
}
impl SessionState {
    pub(crate) const fn new() -> Self {
        Self {
            epoch: AtomicU32::new(0),
            serial_epoch: AtomicU32::new(0),
            configured: AtomicBool::new(false),
        }
    }
    pub fn epoch(&self) -> u32 {
        self.epoch.load(Ordering::Acquire)
    }
    pub fn serial_epoch(&self) -> u32 {
        self.serial_epoch.load(Ordering::Acquire)
    }
    pub fn configured(&self) -> bool {
        self.configured.load(Ordering::Acquire)
    }
    pub(crate) fn invalidate(&self) {
        self.configured.store(false, Ordering::Release);
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.serial_changed();
    }
    pub(crate) fn serial_changed(&self) {
        self.serial_epoch.fetch_add(1, Ordering::AcqRel);
    }
    pub(crate) fn configure(&self, configured: bool) {
        if configured {
            self.configured.store(true, Ordering::Release);
        } else {
            self.invalidate();
        }
    }
    /// Recheck before EVERY poll, not just before awaiting endpoint capacity.
    /// Only wrap endpoint writes here; never wrap a flash/programming future.
    pub(crate) async fn guard_write<E>(
        &self,
        interface: Interface,
        epoch: u32,
        operation: impl Future<Output = Result<(), E>>,
    ) -> Result<(), ()> {
        let mut operation = core::pin::pin!(operation);
        poll_fn(|cx| {
            let current = match interface {
                Interface::Hid => self.epoch(),
                Interface::Serial => self.serial_epoch(),
            };
            if !self.configured() || current != epoch {
                return Poll::Ready(Err(()));
            }
            operation
                .as_mut()
                .poll(cx)
                .map(|result| result.map_err(|_| ()))
        })
        .await
    }
}
