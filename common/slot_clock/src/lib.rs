mod manual_slot_clock;
mod metrics;
mod system_time_slot_clock;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use crate::manual_slot_clock::ManualSlotClock as TestingSlotClock;
pub use crate::manual_slot_clock::ManualSlotClock;
pub use crate::system_time_slot_clock::SystemTimeSlotClock;
pub use metrics::scrape_for_metrics;
pub use types::Slot;

/// A clock that reports the current slot.
///
/// The clock is not required to be monotonically increasing and may go backwards.
pub trait SlotClock: Send + Sync + Sized + Clone {
    /// Creates a new slot clock where the first slot is `genesis_slot`, genesis occurred
    /// `genesis_duration` after the `UNIX_EPOCH` and each slot is `slot_duration` apart.
    fn new(genesis_slot: Slot, genesis_duration: Duration, slot_duration: Duration) -> Self;

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

    /// Returns the duration between slots
    fn slot_duration(&self) -> Duration;

    /// Returns the duration from now until `slot`.
    fn duration_to_slot(&self, slot: Slot) -> Option<Duration>;

    /// Returns the duration until the next slot.
    fn duration_to_next_slot(&self) -> Option<Duration>;

    /// Returns the soonest slot whose deadline has not yet elapsed, and the wait until that
    /// deadline.
    ///
    /// The deadline for a slot is `start_of(slot) + offset_for_slot(slot)`. If `now` is at or
    /// before the current slot's deadline, that slot is returned (the wait may be zero).
    /// Otherwise the next slot is returned.
    ///
    /// `now` should be a single snapshot from `now_duration()`.
    fn duration_to_deadline<F: Fn(Slot) -> Duration>(
        &self,
        now: Duration,
        offset_for_slot: F,
    ) -> Option<(Slot, Duration)> {
        let current_slot = self.slot_of(now).unwrap_or_else(|| self.genesis_slot());
        let current_deadline = self
            .start_of(current_slot)?
            .checked_add(offset_for_slot(current_slot))?;
        if let Some(wait) = current_deadline.checked_sub(now) {
            return Some((current_slot, wait));
        }
        let next_slot = current_slot + 1;
        let next_deadline = self
            .start_of(next_slot)?
            .checked_add(offset_for_slot(next_slot))?;
        next_deadline.checked_sub(now).map(|wait| (next_slot, wait))
    }

    /// Like [`Self::duration_to_deadline`], skipping any slot `<= after`.
    ///
    /// Duty loops pass the last attempted slot so a zero wait cannot spin on that slot.
    fn duration_to_deadline_after<F: Fn(Slot) -> Duration>(
        &self,
        now: Duration,
        offset_for_slot: F,
        after: Option<Slot>,
    ) -> Option<(Slot, Duration)> {
        let (slot, wait) = self.duration_to_deadline(now, &offset_for_slot)?;
        let Some(after) = after else {
            return Some((slot, wait));
        };
        if slot > after {
            return Some((slot, wait));
        }
        let next_slot = after + 1;
        let next_deadline = self
            .start_of(next_slot)?
            .checked_add(offset_for_slot(next_slot))?;
        next_deadline.checked_sub(now).map(|wait| (next_slot, wait))
    }

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
        self.now_duration()
            .and_then(|now| now.checked_sub(self.genesis_duration()))
            .map(|duration_into_slot| {
                Duration::from_secs(duration_into_slot.as_secs() % self.slot_duration().as_secs())
            })
    }

    /// Returns the `Duration` since the start of the current `Slot` at milliseconds precision.
    fn millis_from_current_slot_start(&self) -> Option<Duration> {
        self.now_duration()
            .and_then(|now| now.checked_sub(self.genesis_duration()))
            .map(|duration_into_slot| {
                Duration::from_millis(
                    (duration_into_slot.as_millis() % self.slot_duration().as_millis()) as u64,
                )
            })
    }

    /// Produces a *new* slot clock with the same configuration of `self`, except that clock is
    /// "frozen" at the `freeze_at` time.
    ///
    /// This is useful for observing the slot clock at arbitrary fixed points in time.
    fn freeze_at(&self, freeze_at: Duration) -> ManualSlotClock {
        let slot_clock = ManualSlotClock::new(
            self.genesis_slot(),
            self.genesis_duration(),
            self.slot_duration(),
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

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT_DURATION: Duration = Duration::from_secs(12);
    const GENESIS_DURATION: Duration = Duration::from_secs(12);
    const OFFSET: Duration = Duration::from_secs(4);
    const PRE_FORK_OFFSET: Duration = Duration::from_secs(4);
    const POST_FORK_OFFSET: Duration = Duration::from_secs(3);
    const FORK_SLOT: Slot = Slot::new(32);

    fn clock() -> ManualSlotClock {
        ManualSlotClock::new(Slot::new(0), GENESIS_DURATION, SLOT_DURATION)
    }

    fn constant_offset(_slot: Slot) -> Duration {
        OFFSET
    }

    fn fork_aware_offset(slot: Slot) -> Duration {
        if slot >= FORK_SLOT {
            POST_FORK_OFFSET
        } else {
            PRE_FORK_OFFSET
        }
    }

    #[test]
    fn duration_to_deadline_pre_genesis() {
        let clock = clock();
        let now = GENESIS_DURATION - Duration::from_secs(1);
        assert_eq!(
            clock.duration_to_deadline(now, constant_offset),
            Some((Slot::new(0), Duration::from_secs(5)))
        );
    }

    #[test]
    fn duration_to_deadline_at_slot_start() {
        let clock = clock();
        let now = clock.start_of(Slot::new(0)).unwrap();
        assert_eq!(
            clock.duration_to_deadline(now, constant_offset),
            Some((Slot::new(0), OFFSET))
        );
    }

    #[test]
    fn duration_to_deadline_one_ms_before_due() {
        let clock = clock();
        let now = clock.start_of(Slot::new(0)).unwrap() + OFFSET - Duration::from_millis(1);
        assert_eq!(
            clock.duration_to_deadline(now, constant_offset),
            Some((Slot::new(0), Duration::from_millis(1)))
        );
    }

    #[test]
    fn duration_to_deadline_exactly_at_due() {
        let clock = clock();
        let now = clock.start_of(Slot::new(0)).unwrap() + OFFSET;
        assert_eq!(
            clock.duration_to_deadline(now, constant_offset),
            Some((Slot::new(0), Duration::ZERO))
        );
    }

    #[test]
    fn duration_to_deadline_one_ms_after_due() {
        let clock = clock();
        let now = clock.start_of(Slot::new(0)).unwrap() + OFFSET + Duration::from_millis(1);
        let expected_wait = SLOT_DURATION - OFFSET - Duration::from_millis(1) + OFFSET;
        assert_eq!(
            clock.duration_to_deadline(now, constant_offset),
            Some((Slot::new(1), expected_wait))
        );
    }

    #[test]
    fn duration_to_deadline_uses_current_slot_offset_at_fork_boundary() {
        let clock = clock();
        let last_pre_fork = FORK_SLOT - 1;
        let now = clock.start_of(last_pre_fork).unwrap();
        assert_eq!(
            clock.duration_to_deadline(now, fork_aware_offset),
            Some((last_pre_fork, PRE_FORK_OFFSET))
        );
    }

    #[test]
    fn duration_to_deadline_uses_next_slot_offset_after_current_deadline() {
        let clock = clock();
        let last_pre_fork = FORK_SLOT - 1;
        let now =
            clock.start_of(last_pre_fork).unwrap() + PRE_FORK_OFFSET + Duration::from_millis(1);
        let expected_wait =
            SLOT_DURATION - PRE_FORK_OFFSET - Duration::from_millis(1) + POST_FORK_OFFSET;
        assert_eq!(
            clock.duration_to_deadline(now, fork_aware_offset),
            Some((FORK_SLOT, expected_wait))
        );
    }

    #[test]
    fn duration_to_deadline_at_fork_slot_start() {
        let clock = clock();
        let now = clock.start_of(FORK_SLOT).unwrap();
        assert_eq!(
            clock.duration_to_deadline(now, fork_aware_offset),
            Some((FORK_SLOT, POST_FORK_OFFSET))
        );
    }

    #[test]
    fn duration_to_deadline_non_zero_genesis_slot() {
        let genesis_slot = Slot::new(1);
        let genesis_duration = Duration::from_secs(10);
        let slot_duration = Duration::from_secs(1);
        let offset = Duration::from_millis(200);
        let clock = ManualSlotClock::new(genesis_slot, genesis_duration, slot_duration);
        let now = genesis_duration;
        assert_eq!(
            clock.duration_to_deadline(now, |_| offset),
            Some((genesis_slot, offset))
        );
    }

    #[test]
    fn duration_to_deadline_pre_genesis_with_non_zero_genesis_slot() {
        let genesis_slot = Slot::new(1);
        let genesis_duration = Duration::from_secs(10);
        let slot_duration = Duration::from_secs(1);
        let offset = Duration::from_millis(200);
        let clock = ManualSlotClock::new(genesis_slot, genesis_duration, slot_duration);
        let now = Duration::from_secs(5);
        assert_eq!(
            clock.duration_to_deadline(now, |_| offset),
            Some((genesis_slot, Duration::from_secs(5) + offset))
        );
    }

    #[test]
    fn duration_to_deadline_after_none_matches_duration_to_deadline() {
        let clock = clock();
        let now = clock.start_of(Slot::new(0)).unwrap();
        assert_eq!(
            clock.duration_to_deadline_after(now, constant_offset, None),
            clock.duration_to_deadline(now, constant_offset)
        );
    }

    #[test]
    fn duration_to_deadline_after_exact_due_skips_attempted_slot() {
        let clock = clock();
        let slot = Slot::new(0);
        let now = clock.start_of(slot).unwrap() + OFFSET;
        let expected_wait = SLOT_DURATION - OFFSET + OFFSET;
        assert_eq!(
            clock.duration_to_deadline_after(now, constant_offset, Some(slot)),
            Some((Slot::new(1), expected_wait))
        );
    }

    #[test]
    fn duration_to_deadline_after_before_due_skips_attempted_slot() {
        let clock = clock();
        let slot = Slot::new(0);
        let now = clock.start_of(slot).unwrap();
        let expected_wait = SLOT_DURATION + OFFSET;
        assert_eq!(
            clock.duration_to_deadline_after(now, constant_offset, Some(slot)),
            Some((Slot::new(1), expected_wait))
        );
    }

    #[test]
    fn duration_to_deadline_after_already_in_next_slot_before_due() {
        let clock = clock();
        let now = clock.start_of(Slot::new(1)).unwrap() + Duration::from_secs(1);
        assert_eq!(
            clock.duration_to_deadline_after(now, constant_offset, Some(Slot::new(0))),
            Some((Slot::new(1), OFFSET - Duration::from_secs(1)))
        );
    }

    #[test]
    fn duration_to_deadline_after_past_next_deadline_skips_to_slot_after_current() {
        let clock = clock();
        let now = clock.start_of(Slot::new(1)).unwrap() + OFFSET + Duration::from_millis(1);
        let expected_wait = SLOT_DURATION - OFFSET - Duration::from_millis(1) + OFFSET;
        assert_eq!(
            clock.duration_to_deadline_after(now, constant_offset, Some(Slot::new(0))),
            Some((Slot::new(2), expected_wait))
        );
    }
}
