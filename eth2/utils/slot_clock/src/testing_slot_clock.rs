use super::SlotClock;
use std::sync::RwLock;
use std::time::Duration;
use types::Slot;

#[derive(Debug, PartialEq)]
pub enum Error {}

/// Determines the present slot based upon the present system time.
pub struct TestingSlotClock {
    slot: RwLock<Slot>,
}

impl TestingSlotClock {
    pub fn set_slot(&self, slot: u64) {
        *self.slot.write().expect("TestingSlotClock poisoned.") = Slot::from(slot);
    }

    pub fn advance_slot(&self) {
        self.set_slot(self.present_slot().unwrap().unwrap().as_u64() + 1)
    }
}

impl SlotClock for TestingSlotClock {
    type Error = Error;

    /// Create a new `TestingSlotClock` at `genesis_slot`.
    fn new(genesis_slot: Slot, _genesis_seconds: u64, _slot_duration_seconds: u64) -> Self {
        TestingSlotClock {
            slot: RwLock::new(genesis_slot),
        }
    }

    fn present_slot(&self) -> Result<Option<Slot>, Error> {
        let slot = *self.slot.read().expect("TestingSlotClock poisoned.");
        Ok(Some(slot))
    }

    /// Always returns a duration of 1 second.
    fn duration_to_next_slot(&self) -> Result<Option<Duration>, Error> {
        Ok(Some(Duration::from_secs(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_now() {
        let null = 0;

        let clock = TestingSlotClock::new(Slot::new(10), null, null);
        assert_eq!(clock.present_slot(), Ok(Some(Slot::new(10))));
        clock.set_slot(123);
        assert_eq!(clock.present_slot(), Ok(Some(Slot::new(123))));
    }
}
