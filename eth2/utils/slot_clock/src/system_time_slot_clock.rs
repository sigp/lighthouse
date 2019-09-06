use super::SlotClock;
use std::time::{Duration, Instant};
use types::Slot;

pub use std::time::SystemTimeError;

/// Determines the present slot based upon the present system time.
#[derive(Clone)]
pub struct SystemTimeSlotClock {
    genesis_slot: Slot,
    genesis: Instant,
    slot_duration: Duration,
}

impl SlotClock for SystemTimeSlotClock {
    fn new(genesis_slot: Slot, genesis: Instant, slot_duration: Duration) -> Self {
        if slot_duration.as_millis() == 0 {
            panic!("SystemTimeSlotClock cannot have a < 1ms slot duration.");
        }

        Self {
            genesis_slot,
            genesis,
            slot_duration,
        }
    }

    fn now(&self) -> Option<Slot> {
        let now = Instant::now();

        if now < self.genesis {
            None
        } else {
            let slot = Slot::from(
                (now.duration_since(self.genesis).as_millis() / self.slot_duration.as_millis())
                    as u64,
            );
            Some(slot + self.genesis_slot)
        }
    }

    fn duration_to_next_slot(&self) -> Option<Duration> {
        let now = Instant::now();
        if now < self.genesis {
            Some(self.genesis - now)
        } else {
            let duration_since_genesis = now - self.genesis;
            let millis_since_genesis = duration_since_genesis.as_millis();
            let millis_per_slot = self.slot_duration.as_millis();

            let current_slot = millis_since_genesis / millis_per_slot;
            let next_slot = current_slot + 1;

            let next_slot =
                self.genesis + Duration::from_millis((next_slot * millis_per_slot) as u64);

            Some(next_slot.duration_since(now))
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

        let prior_genesis =
            |seconds_prior: u64| Instant::now() - Duration::from_secs(seconds_prior);

        let clock =
            SystemTimeSlotClock::new(genesis_slot, prior_genesis(0), Duration::from_secs(1));
        assert_eq!(clock.now(), Some(Slot::new(0)));

        let clock =
            SystemTimeSlotClock::new(genesis_slot, prior_genesis(5), Duration::from_secs(1));
        assert_eq!(clock.now(), Some(Slot::new(5)));

        let clock = SystemTimeSlotClock::new(
            genesis_slot,
            Instant::now() - Duration::from_millis(500),
            Duration::from_secs(1),
        );
        assert_eq!(clock.now(), Some(Slot::new(0)));
        assert!(clock.duration_to_next_slot().unwrap() < Duration::from_millis(500));

        let clock = SystemTimeSlotClock::new(
            genesis_slot,
            Instant::now() - Duration::from_millis(1_500),
            Duration::from_secs(1),
        );
        assert_eq!(clock.now(), Some(Slot::new(1)));
        assert!(clock.duration_to_next_slot().unwrap() < Duration::from_millis(500));
    }

    #[test]
    #[should_panic]
    fn zero_seconds() {
        SystemTimeSlotClock::new(Slot::new(0), Instant::now(), Duration::from_secs(0));
    }

    #[test]
    #[should_panic]
    fn zero_millis() {
        SystemTimeSlotClock::new(Slot::new(0), Instant::now(), Duration::from_millis(0));
    }

    #[test]
    #[should_panic]
    fn less_than_one_millis() {
        SystemTimeSlotClock::new(Slot::new(0), Instant::now(), Duration::from_nanos(999));
    }
}
