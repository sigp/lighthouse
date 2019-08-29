use super::SlotClock;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use types::Slot;

/// A slot clock where the slot is manually set instead of being determined by the system time.
///
/// Useful for testing scenarios.
pub struct TestingSlotClock {
    slot: RwLock<Slot>,
}

impl TestingSlotClock {
    pub fn set_slot(&self, slot: u64) {
        *self.slot.write().expect("TestingSlotClock poisoned.") = Slot::from(slot);
    }

    pub fn advance_slot(&self) {
        self.set_slot(self.present_slot().unwrap().as_u64() + 1)
    }
}

impl SlotClock for TestingSlotClock {
    fn new(genesis_slot: Slot, _genesis: Instant, _slot_duration: Duration) -> Self {
        TestingSlotClock {
            slot: RwLock::new(genesis_slot),
        }
    }

    fn present_slot(&self) -> Option<Slot> {
        let slot = *self.slot.read().expect("TestingSlotClock poisoned.");
        Some(slot)
    }

    /// Always returns a duration of 1 second.
    fn duration_to_next_slot(&self) -> Option<Duration> {
        Some(Duration::from_secs(1))
    }

    /// Always returns a slot duration of 0 seconds.
    fn slot_duration(&self) -> Duration {
        Duration::from_secs(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_now() {
        let clock = TestingSlotClock::new(Slot::new(10), Instant::now(), Duration::from_secs(0));
        assert_eq!(clock.present_slot(), Some(Slot::new(10)));
        clock.set_slot(123);
        assert_eq!(clock.present_slot(), Some(Slot::new(123)));
    }
}
