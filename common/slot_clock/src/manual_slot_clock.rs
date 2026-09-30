use super::SlotClock;
use parking_lot::RwLock;
use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;
use types::{Slot, SlotDurationSchedule};

/// Determines the present slot based upon a manually-incremented UNIX timestamp.
pub struct ManualSlotClock {
    genesis_slot: Slot,
    /// Duration from UNIX epoch to genesis.
    genesis_duration: Duration,
    /// Duration from UNIX epoch to right now.
    current_time: Arc<RwLock<Duration>>,
    slot_duration_schedule: SlotDurationSchedule,
    slots_per_epoch: u64,
}

impl Clone for ManualSlotClock {
    fn clone(&self) -> Self {
        ManualSlotClock {
            genesis_slot: self.genesis_slot,
            genesis_duration: self.genesis_duration,
            current_time: Arc::clone(&self.current_time),
            slot_duration_schedule: self.slot_duration_schedule.clone(),
            slots_per_epoch: self.slots_per_epoch,
        }
    }
}

impl ManualSlotClock {
    pub fn set_slot(&self, slot: u64) {
        *self.current_time.write() = self
            .start_of(Slot::new(slot))
            .expect("slot must be post-genesis");
    }

    pub fn set_current_time(&self, duration: Duration) {
        *self.current_time.write() = duration;
    }

    pub fn advance_time(&self, duration: Duration) {
        let current_time = *self.current_time.read();
        *self.current_time.write() = current_time.add(duration);
    }

    pub fn advance_slot(&self) {
        self.set_slot(self.now().unwrap().as_u64() + 1)
    }

    pub fn genesis_duration(&self) -> &Duration {
        &self.genesis_duration
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
    fn from_schedule(
        genesis_slot: Slot,
        genesis_duration: Duration,
        slot_duration_schedule: SlotDurationSchedule,
        slots_per_epoch: u64,
    ) -> Self {
        let entries = slot_duration_schedule.as_vec();
        if entries.last().is_none_or(|entry| entry.epoch != 0) {
            panic!("ManualSlotClock needs a slot duration schedule that starts at epoch 0");
        }
        if entries.iter().any(|entry| entry.slot_duration_ms == 0) {
            panic!("ManualSlotClock cannot have a < 1ms slot duration");
        }

        Self {
            genesis_slot,
            current_time: Arc::new(RwLock::new(genesis_duration)),
            genesis_duration,
            slot_duration_schedule,
            slots_per_epoch,
        }
    }

    fn slot_duration_schedule(&self) -> &SlotDurationSchedule {
        &self.slot_duration_schedule
    }

    fn slots_per_epoch(&self) -> u64 {
        self.slots_per_epoch
    }

    fn now(&self) -> Option<Slot> {
        self.slot_of(*self.current_time.read())
    }

    fn is_prior_to_genesis(&self) -> Option<bool> {
        Some(*self.current_time.read() < self.genesis_duration)
    }

    fn now_duration(&self) -> Option<Duration> {
        Some(*self.current_time.read())
    }

    fn slot_of(&self, now: Duration) -> Option<Slot> {
        let since_genesis = now.checked_sub(self.genesis_duration)?;
        let slot = self
            .slot_duration_schedule
            .compute_slot_at_time_ms(self.slots_per_epoch, 0, since_genesis.as_millis() as u64)
            .ok()?;
        Some(slot + self.genesis_slot)
    }

    fn duration_to_next_slot(&self) -> Option<Duration> {
        self.duration_to_next_slot_from(*self.current_time.read())
    }

    fn duration_to_next_epoch(&self, slots_per_epoch: u64) -> Option<Duration> {
        self.duration_to_next_epoch_from(*self.current_time.read(), slots_per_epoch)
    }

    fn duration_to_slot(&self, slot: Slot) -> Option<Duration> {
        self.duration_to_slot(slot, *self.current_time.read())
    }

    /// Returns the duration between UNIX epoch and the start of `slot`.
    fn start_of(&self, slot: Slot) -> Option<Duration> {
        let slots_since_genesis = slot.as_u64().checked_sub(self.genesis_slot.as_u64())?;
        let time_ms = self
            .slot_duration_schedule
            .compute_time_at_slot_ms(self.slots_per_epoch, 0, Slot::new(slots_since_genesis))
            .ok()?;
        self.genesis_duration
            .checked_add(Duration::from_millis(time_ms))
    }

    fn genesis_slot(&self) -> Slot {
        self.genesis_slot
    }

    fn genesis_duration(&self) -> Duration {
        self.genesis_duration
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
    fn test_is_prior_to_genesis() {
        let genesis_secs = 1;

        let clock = ManualSlotClock::new(
            Slot::new(0),
            Duration::from_secs(genesis_secs),
            Duration::from_secs(1),
        );

        *clock.current_time.write() = Duration::from_secs(genesis_secs - 1);
        assert!(clock.is_prior_to_genesis().unwrap(), "prior to genesis");

        *clock.current_time.write() = Duration::from_secs(genesis_secs);
        assert!(!clock.is_prior_to_genesis().unwrap(), "at genesis");

        *clock.current_time.write() = Duration::from_secs(genesis_secs + 1);
        assert!(!clock.is_prior_to_genesis().unwrap(), "after genesis");
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

    mod slot_duration_schedule {
        use super::*;
        use types::{ChainSpec, Epoch, EthSpec, MainnetEthSpec, SlotDurationScheduleEntry};

        const GENESIS: Duration = Duration::from_secs(1_606_824_023);

        fn spec_with_schedule(entries: &[(u64, u64)]) -> ChainSpec {
            let schedule = SlotDurationSchedule::new(
                entries
                    .iter()
                    .map(|&(epoch, slot_duration_ms)| SlotDurationScheduleEntry {
                        epoch: Epoch::new(epoch),
                        slot_duration_ms,
                    })
                    .collect(),
            );
            ChainSpec::mainnet().set_slot_duration_schedule::<MainnetEthSpec>(schedule)
        }

        fn multi_era_spec() -> ChainSpec {
            spec_with_schedule(&[(0, 12000), (10, 10000), (20, 6000)])
        }

        #[test]
        fn clock_matches_spec_time_functions() {
            let spec = multi_era_spec();
            let clock = ManualSlotClock::from_spec::<MainnetEthSpec>(GENESIS, &spec);
            let genesis_ms = GENESIS.as_millis() as u64;
            for slot in (0..1024).map(Slot::new) {
                let spec_start_ms = spec
                    .slot_duration_schedule()
                    .compute_time_at_slot_ms(MainnetEthSpec::slots_per_epoch(), genesis_ms, slot)
                    .unwrap();
                let start = clock.start_of(slot).unwrap();
                assert_eq!(start, Duration::from_millis(spec_start_ms), "slot {slot}");
                assert_eq!(clock.slot_of(start), Some(slot), "slot {slot}");
                let next_start = clock.start_of(slot + 1).unwrap();
                assert_eq!(
                    clock.slot_of(next_start - Duration::from_millis(1)),
                    Some(slot),
                    "slot {slot}"
                );
                assert_eq!(
                    clock.slot_duration_at(slot),
                    Duration::from_millis(
                        spec.get_slot_duration_ms(slot.epoch(MainnetEthSpec::slots_per_epoch()))
                    ),
                    "slot {slot}"
                );
            }
            assert_eq!(clock.slot_of(GENESIS - Duration::from_millis(1)), None);
        }

        #[test]
        fn single_entry_schedule_matches_fixed_duration() {
            let from_spec =
                ManualSlotClock::from_spec::<MainnetEthSpec>(GENESIS, &ChainSpec::mainnet());
            let fixed = ManualSlotClock::new(Slot::new(0), GENESIS, Duration::from_secs(12));
            for slot in [0, 1, 31, 32, 12_345].map(Slot::new) {
                assert_eq!(from_spec.start_of(slot), fixed.start_of(slot));
            }
        }

        #[test]
        fn clock_follows_slot_duration_changes() {
            let clock = ManualSlotClock::from_spec::<MainnetEthSpec>(GENESIS, &multi_era_spec());

            clock.set_slot(319);
            assert_eq!(clock.slot_duration(), Duration::from_secs(12));
            assert_eq!(clock.duration_to_next_slot(), Some(Duration::from_secs(12)));

            clock.advance_slot();
            assert_eq!(clock.now(), Some(Slot::new(320)));
            assert_eq!(clock.slot_duration(), Duration::from_secs(10));
            assert_eq!(
                clock.slot_duration_at(Slot::new(319)),
                Duration::from_secs(12)
            );

            clock.advance_time(Duration::from_millis(12_500));
            assert_eq!(clock.now(), Some(Slot::new(321)));
            assert_eq!(
                clock.millis_from_current_slot_start(),
                Some(Duration::from_millis(2_500))
            );
            assert_eq!(
                clock.seconds_from_current_slot_start(),
                Some(Duration::from_secs(2))
            );

            clock.set_slot(630);
            assert_eq!(
                clock.duration_to_next_epoch(MainnetEthSpec::slots_per_epoch()),
                Some(Duration::from_secs(100))
            );

            clock.set_slot(640);
            assert_eq!(clock.slot_duration(), Duration::from_secs(6));
            clock.advance_time(Duration::from_secs(6));
            assert_eq!(clock.now(), Some(Slot::new(641)));

            let frozen = clock.freeze_at(clock.start_of(Slot::new(700)).unwrap());
            assert_eq!(frozen.now(), Some(Slot::new(700)));
            assert_eq!(
                frozen.slot_duration_schedule(),
                clock.slot_duration_schedule()
            );
        }
    }
}
