mod manual_slot_clock;
mod metrics;
mod system_time_slot_clock;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use crate::manual_slot_clock::ManualSlotClock as TestingSlotClock;
pub use crate::manual_slot_clock::ManualSlotClock;
pub use crate::system_time_slot_clock::SystemTimeSlotClock;
pub use metrics::scrape_for_metrics;
pub use types::Slot;
use types::{ChainSpec, Epoch, EthSpec, SlotDurationSchedule, SlotDurationScheduleEntry};

/// A clock that reports the current slot.
///
/// The clock is not required to be monotonically increasing and may go backwards.
pub trait SlotClock: Send + Sync + Sized + Clone {
    /// Creates a new slot clock where the first slot is `genesis_slot`, genesis occurred
    /// `genesis_duration` after the `UNIX_EPOCH` and each slot is `slot_duration` apart.
    fn new(genesis_slot: Slot, genesis_duration: Duration, slot_duration: Duration) -> Self {
        let slot_duration_schedule = SlotDurationSchedule::new(vec![SlotDurationScheduleEntry {
            epoch: Epoch::new(0),
            slot_duration_ms: slot_duration.as_millis() as u64,
        }]);
        // A schedule with only a genesis entry reads the same for any number of slots per epoch.
        Self::from_schedule(genesis_slot, genesis_duration, slot_duration_schedule, 1)
    }

    /// Creates a new slot clock that follows the slot duration schedule of `spec`.
    fn from_spec<E: EthSpec>(genesis_duration: Duration, spec: &ChainSpec) -> Self {
        Self::from_schedule(
            spec.genesis_slot,
            genesis_duration,
            spec.slot_duration_schedule(),
            E::slots_per_epoch(),
        )
    }

    /// Creates a new slot clock where the first slot is `genesis_slot`, genesis occurred
    /// `genesis_duration` after the `UNIX_EPOCH` and slot durations follow `slot_duration_schedule`.
    fn from_schedule(
        genesis_slot: Slot,
        genesis_duration: Duration,
        slot_duration_schedule: SlotDurationSchedule,
        slots_per_epoch: u64,
    ) -> Self;

    /// Returns the slot duration schedule the clock follows.
    fn slot_duration_schedule(&self) -> &SlotDurationSchedule;

    /// Returns the number of slots per epoch used to read the slot duration schedule.
    fn slots_per_epoch(&self) -> u64;

    /// Returns the slot at this present time.
    fn now(&self) -> Option<Slot>;

    /// Returns the slot at this present time if genesis has happened. Otherwise, returns the
    /// genesis slot. Returns `None` if there is an error reading the clock.
    fn now_or_genesis(&self) -> Option<Slot> {
        if self.is_prior_to_genesis()? {
            Some(self.genesis_slot())
        } else {
            self.now()
        }
    }

    /// Indicates if the current time is prior to genesis time.
    ///
    /// Returns `None` if the system clock cannot be read.
    fn is_prior_to_genesis(&self) -> Option<bool>;

    /// Returns the present time as a duration since the UNIX epoch.
    ///
    /// Returns `None` if the present time is before the UNIX epoch (unlikely).
    fn now_duration(&self) -> Option<Duration>;

    /// Returns the slot of the given duration since the UNIX epoch.
    fn slot_of(&self, now: Duration) -> Option<Slot>;

    /// Returns the duration of the current slot, or of the genesis slot prior to genesis.
    fn slot_duration(&self) -> Duration {
        self.slot_duration_at(self.now().unwrap_or(self.genesis_slot()))
    }

    /// Returns the duration of `slot`.
    fn slot_duration_at(&self, slot: Slot) -> Duration {
        let slots_since_genesis = slot.as_u64().saturating_sub(self.genesis_slot().as_u64());
        let epoch = Slot::new(slots_since_genesis).epoch(self.slots_per_epoch());
        Duration::from_millis(
            self.slot_duration_schedule()
                .slot_duration_ms_for_epoch(epoch)
                .unwrap_or_default(),
        )
    }

    /// Returns the duration from now until `slot`.
    fn duration_to_slot(&self, slot: Slot) -> Option<Duration>;

    /// Returns the duration until the next slot.
    fn duration_to_next_slot(&self) -> Option<Duration>;

    /// Returns the duration until the first slot of the next epoch.
    fn duration_to_next_epoch(&self, slots_per_epoch: u64) -> Option<Duration>;

    /// Returns the start time of the slot, as a duration since `UNIX_EPOCH`.
    fn start_of(&self, slot: Slot) -> Option<Duration>;

    /// Returns the first slot to be returned at the genesis time.
    fn genesis_slot(&self) -> Slot;

    /// Returns the `Duration` from `UNIX_EPOCH` to the genesis time.
    fn genesis_duration(&self) -> Duration;

    /// Returns the slot if the internal clock were advanced by `duration`.
    fn now_with_future_tolerance(&self, tolerance: Duration) -> Option<Slot> {
        self.slot_of(self.now_duration()?.checked_add(tolerance)?)
    }

    /// Returns the slot if the internal clock were reversed by `duration`.
    fn now_with_past_tolerance(&self, tolerance: Duration) -> Option<Slot> {
        self.slot_of(self.now_duration()?.checked_sub(tolerance)?)
            .or_else(|| Some(self.genesis_slot()))
    }

    /// Returns the `Duration` since the start of the current `Slot` at seconds precision. Useful in determining whether to apply proposer boosts.
    fn seconds_from_current_slot_start(&self) -> Option<Duration> {
        self.duration_from_current_slot_start()
            .map(|duration_into_slot| Duration::from_secs(duration_into_slot.as_secs()))
    }

    /// Returns the `Duration` since the start of the current `Slot` at milliseconds precision.
    fn millis_from_current_slot_start(&self) -> Option<Duration> {
        self.duration_from_current_slot_start()
            .map(|duration_into_slot| Duration::from_millis(duration_into_slot.as_millis() as u64))
    }

    /// Returns the `Duration` since the start of the current `Slot`.
    fn duration_from_current_slot_start(&self) -> Option<Duration> {
        let now = self.now_duration()?;
        now.checked_sub(self.start_of(self.slot_of(now)?)?)
    }

    /// Produces a *new* slot clock with the same configuration of `self`, except that clock is
    /// "frozen" at the `freeze_at` time.
    ///
    /// This is useful for observing the slot clock at arbitrary fixed points in time.
    fn freeze_at(&self, freeze_at: Duration) -> ManualSlotClock {
        let slot_clock = ManualSlotClock::from_schedule(
            self.genesis_slot(),
            self.genesis_duration(),
            self.slot_duration_schedule().clone(),
            self.slots_per_epoch(),
        );
        slot_clock.set_current_time(freeze_at);
        slot_clock
    }
}

/// Returns the current system time as a duration since the UNIX epoch.
///
/// This is a convenience function for recording timestamps when `SlotClock` is not available.
/// Prefer `SlotClock::now_duration` if available.
pub fn timestamp_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}
