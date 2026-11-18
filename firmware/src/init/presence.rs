//! A one-use, expiring local confirmation. Feed this only from a trusted GPIO
//! observer and monotonic clock, never host-supplied timestamps/button values.
pub const HOLD_MS: u64 = 3000;
pub const DEBOUNCE_MS: u64 = 30;
pub const WINDOW_MS: u64 = 30_000;
pub const CONFIRMATION_TTL_MS: u64 = 10_000;

pub struct Confirmation {
    issued: u64,
}
impl Confirmation {
    pub(super) fn valid(self, now: u64) -> bool {
        now.checked_sub(self.issued)
            .is_some_and(|age| age <= CONFIRMATION_TTL_MS)
    }
}
enum Phase {
    Release(Option<u64>),
    Press,
    Hold(u64),
    Finish(Option<u64>),
    Done,
}
pub struct PresenceGate {
    started: u64,
    last: u64,
    phase: Phase,
}
impl PresenceGate {
    pub fn new(now: u64) -> Self {
        Self {
            started: now,
            last: now,
            phase: Phase::Release(None),
        }
    }
    pub fn expired(&self, now: u64) -> bool {
        now < self.last
            || now
                .checked_sub(self.started)
                .is_none_or(|age| age > WINDOW_MS)
    }
    /// Require stable initial release, a fresh continuous hold and stable final
    /// release. Holding the button at boot never confirms setup on its own.
    pub fn observe(&mut self, pressed: bool, now: u64) -> Option<Confirmation> {
        if self.expired(now) {
            self.phase = Phase::Done;
            return None;
        }
        self.last = now;
        match &mut self.phase {
            Phase::Release(since) => {
                if pressed {
                    *since = None;
                } else if now - *since.get_or_insert(now) >= DEBOUNCE_MS {
                    self.phase = Phase::Press;
                }
            }
            Phase::Press if pressed => self.phase = Phase::Hold(now),
            Phase::Hold(since) => {
                if !pressed {
                    self.phase = Phase::Press;
                } else if now - *since >= HOLD_MS {
                    self.phase = Phase::Finish(None);
                }
            }
            Phase::Finish(since) => {
                if pressed {
                    *since = None;
                } else if now - *since.get_or_insert(now) >= DEBOUNCE_MS {
                    self.phase = Phase::Done;
                    return Some(Confirmation { issued: now });
                }
            }
            _ => {}
        }
        None
    }
}
