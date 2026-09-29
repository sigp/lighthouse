mod manual_slot_clock;
mod metrics;
mod system_time_slot_clock;
mod timeline;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use crate::manual_slot_clock::ManualSlotClock as TestingSlotClock;
pub use crate::manual_slot_clock::ManualSlotClock;
pub use crate::system_time_slot_clock::SystemTimeSlotClock;
pub use metrics::scrape_for_metrics;
pub use timeline::SlotTimeline;
pub use types::Slot;

/// A clock that reports the current slot.
///
/// The clock is not required to be monotonically increasing and may go backwards.
pub trait SlotClock: Send + Sync + Sized + Clone {
    /// Creates a new slot clock where the first slot is `genesis_slot`, genesis occurred
    /// `genesis_duration` after the `UNIX_EPOCH` and each slot is `slot_duration` apart.
    fn new(genesis_slot: Slot, genesis_duration: Duration, slot_duration: Duration) -> Self {
        Self::from_timeline(SlotTimeline::new(
            genesis_slot,
            genesis_duration,
            slot_duration,
        ))
    }

    /// Creates a new slot clock that follows the slot duration schedule of `timeline`.
    fn from_timeline(timeline: SlotTimeline) -> Self;

    /// Returns the mapping between wall-clock time and slots.
    fn timeline(&self) -> &SlotTimeline;

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
    fn slot_of(&self, now: Duration) -> Option<Slot> {
        self.timeline().slot_of(now)
    }

    /// Returns the duration of the current slot, or of the genesis slot prior to genesis.
    fn slot_duration(&self) -> Duration {
        self.slot_duration_at(self.now_or_genesis().unwrap_or(self.genesis_slot()))
    }

    /// Returns the duration of `slot`.
    fn slot_duration_at(&self, slot: Slot) -> Duration {
        self.timeline().slot_duration_at(slot)
    }

    /// Returns the duration from now until `slot`.
    fn duration_to_slot(&self, slot: Slot) -> Option<Duration>;

    /// Returns the duration until the next slot.
    fn duration_to_next_slot(&self) -> Option<Duration>;

    /// Returns the duration until the first slot of the next epoch.
    fn duration_to_next_epoch(&self, slots_per_epoch: u64) -> Option<Duration>;

    /// Returns the start time of the slot, as a duration since `UNIX_EPOCH`.
    fn start_of(&self, slot: Slot) -> Option<Duration> {
        self.timeline().start_of(slot)
    }

    /// Returns the first slot to be returned at the genesis time.
    fn genesis_slot(&self) -> Slot {
        self.timeline().genesis_slot()
    }

    /// Returns the `Duration` from `UNIX_EPOCH` to the genesis time.
    fn genesis_duration(&self) -> Duration {
        self.timeline().genesis_duration()
    }

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
        let slot_clock = ManualSlotClock::from_timeline(self.timeline().clone());
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
