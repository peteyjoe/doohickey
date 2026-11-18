//! A fresh debounced release -> press -> release, scoped to one request.
use super::{Result, Status};
const DEBOUNCE_MS: u64 = 30;
enum Phase {
    Release(Option<u64>),
    Press(Option<u64>),
    Finish(Option<u64>),
    Consumed,
}
pub struct Gate {
    phase: Phase,
    deadline: u64,
}
impl Gate {
    pub fn new(now: u64, timeout_ms: u32) -> Self {
        Self {
            phase: Phase::Release(None),
            deadline: now.saturating_add(u64::from(timeout_ms)),
        }
    }
    pub fn observe(&mut self, pressed: bool, now: u64) -> Result<bool> {
        if now >= self.deadline {
            return Err(Status::OperationDenied);
        }
        let (since, expected) = match &mut self.phase {
            Phase::Release(since) | Phase::Finish(since) => (since, false),
            Phase::Press(since) => (since, true),
            Phase::Consumed => return Ok(false),
        };
        if pressed != expected {
            *since = None;
            return Ok(false);
        }
        let started = *since.get_or_insert(now);
        if now.saturating_sub(started) < DEBOUNCE_MS {
            return Ok(false);
        }
        self.phase = match self.phase {
            Phase::Release(_) => Phase::Press(None),
            Phase::Press(_) => Phase::Finish(None),
            Phase::Finish(_) => {
                self.phase = Phase::Consumed;
                return Ok(true);
            }
            Phase::Consumed => unreachable!(),
        };
        Ok(false)
    }
}
