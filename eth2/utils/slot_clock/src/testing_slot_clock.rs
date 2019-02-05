use super::SlotClock;
use std::sync::RwLock;

#[derive(Debug, PartialEq)]
pub enum Error {}

/// Determines the present slot based upon the present system time.
pub struct TestingSlotClock {
    slot: RwLock<u64>,
}

impl TestingSlotClock {
    /// Create a new `TestingSlotClock`.
    ///
    /// Returns an Error if `slot_duration_seconds == 0`.
    pub fn new(slot: u64) -> TestingSlotClock {
        TestingSlotClock {
            slot: RwLock::new(slot),
        }
    }

    pub fn set_slot(&self, slot: u64) {
        *self.slot.write().expect("TestingSlotClock poisoned.") = slot;
    }
}

impl SlotClock for TestingSlotClock {
    type Error = Error;

    fn present_slot(&self) -> Result<Option<u64>, Error> {
        let slot = *self.slot.read().expect("TestingSlotClock poisoned.");
        Ok(Some(slot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_now() {
        let clock = TestingSlotClock::new(10);
        assert_eq!(clock.present_slot(), Ok(Some(10)));
        clock.set_slot(123);
        assert_eq!(clock.present_slot(), Ok(Some(123)));
    }
}
