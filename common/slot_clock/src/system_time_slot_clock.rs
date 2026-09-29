use super::{ManualSlotClock, SlotClock, SlotTimeline};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use types::Slot;

/// Determines the present slot based upon the present system time.
#[derive(Clone)]
pub struct SystemTimeSlotClock {
    clock: ManualSlotClock,
}

impl SlotClock for SystemTimeSlotClock {
    fn from_timeline(timeline: SlotTimeline) -> Self {
        Self {
            clock: ManualSlotClock::from_timeline(timeline),
        }
    }

    fn timeline(&self) -> &SlotTimeline {
        self.clock.timeline()
    }

    fn now(&self) -> Option<Slot> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        self.clock.slot_of(now)
    }

    fn is_prior_to_genesis(&self) -> Option<bool> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        Some(now < self.clock.genesis_duration())
    }

    fn now_duration(&self) -> Option<Duration> {
        SystemTime::now().duration_since(UNIX_EPOCH).ok()
    }

    fn duration_to_next_slot(&self) -> Option<Duration> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        self.clock.duration_to_next_slot_from(now)
    }

    fn duration_to_next_epoch(&self, slots_per_epoch: u64) -> Option<Duration> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        self.clock.duration_to_next_epoch_from(now, slots_per_epoch)
    }

    fn duration_to_slot(&self, slot: Slot) -> Option<Duration> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        self.clock.duration_to_slot(slot, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /*
     * Note: these tests are using actual system times and could fail if they are executed on a
     * very slow machine.
     */
    #[test]
    fn test_slot_now() {
        let genesis_slot = Slot::new(0);

        let prior_genesis = |milliseconds_prior: u64| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("should get system time")
                - Duration::from_millis(milliseconds_prior)
        };

        let clock =
            SystemTimeSlotClock::new(genesis_slot, prior_genesis(0), Duration::from_secs(1));
        assert_eq!(clock.now(), Some(Slot::new(0)));

        let clock =
            SystemTimeSlotClock::new(genesis_slot, prior_genesis(5_000), Duration::from_secs(1));
        assert_eq!(clock.now(), Some(Slot::new(5)));

        let clock =
            SystemTimeSlotClock::new(genesis_slot, prior_genesis(500), Duration::from_secs(1));
        assert_eq!(clock.now(), Some(Slot::new(0)));
        assert!(clock.duration_to_next_slot().unwrap() <= Duration::from_millis(500));

        let clock =
            SystemTimeSlotClock::new(genesis_slot, prior_genesis(1_500), Duration::from_secs(1));
        assert_eq!(clock.now(), Some(Slot::new(1)));
        assert!(clock.duration_to_next_slot().unwrap() <= Duration::from_millis(500));
    }

    #[test]
    #[should_panic]
    fn zero_seconds() {
        SystemTimeSlotClock::new(Slot::new(0), Duration::from_secs(0), Duration::from_secs(0));
    }

    #[test]
    #[should_panic]
    fn zero_millis() {
        SystemTimeSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            Duration::from_millis(0),
        );
    }

    #[test]
    #[should_panic]
    fn less_than_one_millis() {
        SystemTimeSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            Duration::from_nanos(999),
        );
    }
}
