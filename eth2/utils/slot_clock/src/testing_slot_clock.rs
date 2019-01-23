use super::SlotClock;

#[derive(Debug, PartialEq)]
pub enum Error {}

/// Determines the present slot based upon the present system time.
pub struct TestingSlotClock {
    slot: u64,
}

impl TestingSlotClock {
    /// Create a new `TestingSlotClock`.
    ///
    /// Returns an Error if `slot_duration_seconds == 0`.
    pub fn new(slot: u64) -> TestingSlotClock {
        TestingSlotClock { slot }
    }

    pub fn set_slot(&mut self, slot: u64) {
        self.slot = slot;
    }
}

impl SlotClock for TestingSlotClock {
    type Error = Error;

    fn present_slot(&self) -> Result<Option<u64>, Error> {
        Ok(Some(self.slot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_now() {
        let mut clock = TestingSlotClock::new(10);
        assert_eq!(clock.present_slot(), Ok(Some(10)));
        clock.set_slot(123);
        assert_eq!(clock.present_slot(), Ok(Some(123)));
    }
}
