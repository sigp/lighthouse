use super::SlotClock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use types::Slot;

pub use std::time::SystemTimeError;

/// Determines the present slot based upon the present system time.
#[derive(Clone)]
pub struct SystemTimeSlotClock {
    genesis_slot: Slot,
    genesis_duration: Duration,
    slot_duration: Duration,
}

impl SlotClock for SystemTimeSlotClock {
    fn new(genesis_slot: Slot, genesis_duration: Duration, slot_duration: Duration) -> Self {
        if slot_duration.as_millis() == 0 {
            panic!("SystemTimeSlotClock cannot have a < 1ms slot duration.");
        }

        Self {
            genesis_slot,
            genesis_duration,
            slot_duration,
        }
    }

    fn now(&self) -> Option<Slot> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        let genesis = self.genesis_duration;

        if now > genesis {
            let since_genesis = now
                .checked_sub(genesis)
                .expect("Control flow ensures now is greater than genesis");
            let slot =
                Slot::from((since_genesis.as_millis() / self.slot_duration.as_millis()) as u64);
            Some(slot + self.genesis_slot)
        } else {
            None
        }
    }

    fn duration_to_next_slot(&self) -> Option<Duration> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        let genesis = self.genesis_duration;

        let slot_start = |slot: Slot| -> Duration {
            let slot = slot.as_u64() as u32;
            genesis + slot * self.slot_duration
        };

        if now > genesis {
            Some(
                slot_start(self.now()? + 1)
                    .checked_sub(now)
                    .expect("The next slot cannot start before now"),
            )
        } else {
            Some(
                genesis
                    .checked_sub(now)
                    .expect("Control flow ensures genesis is greater than or equal to now"),
            )
        }
    }

    fn slot_duration(&self) -> Duration {
        self.slot_duration
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
        assert!(clock.duration_to_next_slot().unwrap() < Duration::from_millis(500));

        let clock =
            SystemTimeSlotClock::new(genesis_slot, prior_genesis(1_500), Duration::from_secs(1));
        assert_eq!(clock.now(), Some(Slot::new(1)));
        assert!(clock.duration_to_next_slot().unwrap() < Duration::from_millis(500));
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
