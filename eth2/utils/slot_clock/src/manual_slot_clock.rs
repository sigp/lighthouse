use super::SlotClock;
use parking_lot::RwLock;
use std::convert::TryInto;
use std::time::Duration;
use types::Slot;

/// Determines the present slot based upon a manually-incremented UNIX timestamp.
pub struct ManualSlotClock {
    genesis_slot: Slot,
    /// Duration from UNIX epoch to genesis.
    genesis_duration: Duration,
    /// Duration from UNIX epoch to right now.
    current_time: RwLock<Duration>,
    /// The length of each slot.
    slot_duration: Duration,
}

impl Clone for ManualSlotClock {
    fn clone(&self) -> Self {
        ManualSlotClock {
            genesis_slot: self.genesis_slot.clone(),
            genesis_duration: self.genesis_duration.clone(),
            current_time: RwLock::new(self.current_time.read().clone()),
            slot_duration: self.slot_duration.clone(),
        }
    }
}

impl ManualSlotClock {
    pub fn set_slot(&self, slot: u64) {
        let slots_since_genesis = slot
            .checked_sub(self.genesis_slot.as_u64())
            .expect("slot must be post-genesis")
            .try_into()
            .expect("slot must fit within a u32");
        *self.current_time.write() =
            self.genesis_duration + self.slot_duration * slots_since_genesis;
    }

    pub fn advance_slot(&self) {
        self.set_slot(self.now().unwrap().as_u64() + 1)
    }

    /// Returns the duration between UNIX epoch and the start of `slot`.
    pub fn start_of(&self, slot: Slot) -> Option<Duration> {
        let slot = slot
            .as_u64()
            .checked_sub(self.genesis_slot.as_u64())?
            .try_into()
            .ok()?;
        let unadjusted_slot_duration = self.slot_duration.checked_mul(slot)?;

        self.genesis_duration.checked_add(unadjusted_slot_duration)
    }

    /// Returns the duration from `now` until the start of `slot`.
    ///
    /// Will return `None` if `now` is later than the start of `slot`.
    pub fn duration_to_slot(&self, slot: Slot, now: Duration) -> Option<Duration> {
        self.start_of(slot)?.checked_sub(now)
    }

    /// Returns the duration between `now` and the start of the next slot.
    pub fn duration_to_next_slot_from(&self, now: Duration) -> Option<Duration> {
        if now < self.genesis_duration {
            self.genesis_duration.checked_sub(now)
        } else {
            self.duration_to_slot(self.slot_of(now)? + 1, now)
        }
    }

    /// Returns the duration between `now` and the start of the next epoch.
    pub fn duration_to_next_epoch_from(
        &self,
        now: Duration,
        slots_per_epoch: u64,
    ) -> Option<Duration> {
        if now < self.genesis_duration {
            self.genesis_duration.checked_sub(now)
        } else {
            let next_epoch_start_slot =
                (self.slot_of(now)?.epoch(slots_per_epoch) + 1).start_slot(slots_per_epoch);

            self.duration_to_slot(next_epoch_start_slot, now)
        }
    }
}

impl SlotClock for ManualSlotClock {
    fn new(genesis_slot: Slot, genesis_duration: Duration, slot_duration: Duration) -> Self {
        if slot_duration.as_millis() == 0 {
            panic!("ManualSlotClock cannot have a < 1ms slot duration");
        }

        Self {
            genesis_slot,
            current_time: RwLock::new(genesis_duration.clone()),
            genesis_duration,
            slot_duration,
        }
    }

    fn now(&self) -> Option<Slot> {
        self.slot_of(*self.current_time.read())
    }

    fn now_duration(&self) -> Option<Duration> {
        Some(*self.current_time.read())
    }

    fn slot_of(&self, now: Duration) -> Option<Slot> {
        let genesis = self.genesis_duration;

        if now >= genesis {
            let since_genesis = now
                .checked_sub(genesis)
                .expect("Control flow ensures now is greater than or equal to genesis");
            let slot =
                Slot::from((since_genesis.as_millis() / self.slot_duration.as_millis()) as u64);
            Some(slot + self.genesis_slot)
        } else {
            None
        }
    }

    fn duration_to_next_slot(&self) -> Option<Duration> {
        self.duration_to_next_slot_from(*self.current_time.read())
    }

    fn duration_to_next_epoch(&self, slots_per_epoch: u64) -> Option<Duration> {
        self.duration_to_next_epoch_from(*self.current_time.read(), slots_per_epoch)
    }

    fn slot_duration(&self) -> Duration {
        self.slot_duration
    }

    fn genesis_slot(&self) -> Slot {
        self.genesis_slot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_now() {
        let clock = ManualSlotClock::new(
            Slot::new(10),
            Duration::from_secs(0),
            Duration::from_secs(1),
        );
        assert_eq!(clock.now(), Some(Slot::new(10)));
        clock.set_slot(123);
        assert_eq!(clock.now(), Some(Slot::new(123)));
    }

    #[test]
    fn start_of() {
        // Genesis slot and genesis duration 0.
        let clock =
            ManualSlotClock::new(Slot::new(0), Duration::from_secs(0), Duration::from_secs(1));
        assert_eq!(clock.start_of(Slot::new(0)), Some(Duration::from_secs(0)));
        assert_eq!(clock.start_of(Slot::new(1)), Some(Duration::from_secs(1)));
        assert_eq!(clock.start_of(Slot::new(2)), Some(Duration::from_secs(2)));

        // Genesis slot 1 and genesis duration 10.
        let clock = ManualSlotClock::new(
            Slot::new(0),
            Duration::from_secs(10),
            Duration::from_secs(1),
        );
        assert_eq!(clock.start_of(Slot::new(0)), Some(Duration::from_secs(10)));
        assert_eq!(clock.start_of(Slot::new(1)), Some(Duration::from_secs(11)));
        assert_eq!(clock.start_of(Slot::new(2)), Some(Duration::from_secs(12)));

        // Genesis slot 1 and genesis duration 0.
        let clock =
            ManualSlotClock::new(Slot::new(1), Duration::from_secs(0), Duration::from_secs(1));
        assert_eq!(clock.start_of(Slot::new(0)), None);
        assert_eq!(clock.start_of(Slot::new(1)), Some(Duration::from_secs(0)));
        assert_eq!(clock.start_of(Slot::new(2)), Some(Duration::from_secs(1)));

        // Genesis slot 1 and genesis duration 10.
        let clock = ManualSlotClock::new(
            Slot::new(1),
            Duration::from_secs(10),
            Duration::from_secs(1),
        );
        assert_eq!(clock.start_of(Slot::new(0)), None);
        assert_eq!(clock.start_of(Slot::new(1)), Some(Duration::from_secs(10)));
        assert_eq!(clock.start_of(Slot::new(2)), Some(Duration::from_secs(11)));
    }

    #[test]
    fn test_duration_to_next_slot() {
        let slot_duration = Duration::from_secs(1);

        // Genesis time is now.
        let clock = ManualSlotClock::new(Slot::new(0), Duration::from_secs(0), slot_duration);
        *clock.current_time.write() = Duration::from_secs(0);
        assert_eq!(clock.duration_to_next_slot(), Some(Duration::from_secs(1)));

        // Genesis time is in the future.
        let clock = ManualSlotClock::new(Slot::new(0), Duration::from_secs(10), slot_duration);
        *clock.current_time.write() = Duration::from_secs(0);
        assert_eq!(clock.duration_to_next_slot(), Some(Duration::from_secs(10)));

        // Genesis time is in the past.
        let clock = ManualSlotClock::new(Slot::new(0), Duration::from_secs(0), slot_duration);
        *clock.current_time.write() = Duration::from_secs(10);
        assert_eq!(clock.duration_to_next_slot(), Some(Duration::from_secs(1)));
    }

    #[test]
    fn test_duration_to_next_epoch() {
        let slot_duration = Duration::from_secs(1);
        let slots_per_epoch = 32;

        // Genesis time is now.
        let clock = ManualSlotClock::new(Slot::new(0), Duration::from_secs(0), slot_duration);
        *clock.current_time.write() = Duration::from_secs(0);
        assert_eq!(
            clock.duration_to_next_epoch(slots_per_epoch),
            Some(Duration::from_secs(32))
        );

        // Genesis time is in the future.
        let clock = ManualSlotClock::new(Slot::new(0), Duration::from_secs(10), slot_duration);
        *clock.current_time.write() = Duration::from_secs(0);
        assert_eq!(
            clock.duration_to_next_epoch(slots_per_epoch),
            Some(Duration::from_secs(10))
        );

        // Genesis time is in the past.
        let clock = ManualSlotClock::new(Slot::new(0), Duration::from_secs(0), slot_duration);
        *clock.current_time.write() = Duration::from_secs(10);
        assert_eq!(
            clock.duration_to_next_epoch(slots_per_epoch),
            Some(Duration::from_secs(22))
        );

        // Genesis time is in the past.
        let clock = ManualSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            Duration::from_secs(12),
        );
        *clock.current_time.write() = Duration::from_secs(72_333);
        assert!(clock.duration_to_next_epoch(slots_per_epoch).is_some(),);
    }

    #[test]
    fn test_tolerance() {
        let clock = ManualSlotClock::new(
            Slot::new(0),
            Duration::from_secs(10),
            Duration::from_secs(1),
        );

        // Set clock to the 0'th slot.
        *clock.current_time.write() = Duration::from_secs(10);
        assert_eq!(
            clock
                .now_with_future_tolerance(Duration::from_secs(0))
                .unwrap(),
            Slot::new(0),
            "future tolerance of zero should return current slot"
        );
        assert_eq!(
            clock
                .now_with_past_tolerance(Duration::from_secs(0))
                .unwrap(),
            Slot::new(0),
            "past tolerance of zero should return current slot"
        );
        assert_eq!(
            clock
                .now_with_future_tolerance(Duration::from_millis(10))
                .unwrap(),
            Slot::new(0),
            "insignificant future tolerance should return current slot"
        );
        assert_eq!(
            clock
                .now_with_past_tolerance(Duration::from_millis(10))
                .unwrap(),
            Slot::new(0),
            "past tolerance that precedes genesis should return genesis slot"
        );

        // Set clock to part-way through the 1st slot.
        *clock.current_time.write() = Duration::from_millis(11_200);
        assert_eq!(
            clock
                .now_with_future_tolerance(Duration::from_secs(0))
                .unwrap(),
            Slot::new(1),
            "future tolerance of zero should return current slot"
        );
        assert_eq!(
            clock
                .now_with_past_tolerance(Duration::from_secs(0))
                .unwrap(),
            Slot::new(1),
            "past tolerance of zero should return current slot"
        );
        assert_eq!(
            clock
                .now_with_future_tolerance(Duration::from_millis(800))
                .unwrap(),
            Slot::new(2),
            "significant future tolerance should return next slot"
        );
        assert_eq!(
            clock
                .now_with_past_tolerance(Duration::from_millis(201))
                .unwrap(),
            Slot::new(0),
            "significant past tolerance should return previous slot"
        );
    }
}
