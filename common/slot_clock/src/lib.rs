#[macro_use]
extern crate lazy_static;

mod manual_slot_clock;
mod metrics;
mod system_time_slot_clock;

use std::time::Duration;

pub use crate::manual_slot_clock::ManualSlotClock as TestingSlotClock;
pub use crate::manual_slot_clock::ManualSlotClock;
pub use crate::system_time_slot_clock::SystemTimeSlotClock;
pub use metrics::scrape_for_metrics;
use types::consts::merge::INTERVALS_PER_SLOT;
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

    /// Returns the delay between the start of the slot and when unaggregated attestations should be
    /// produced.
    fn unagg_attestation_production_delay(&self) -> Duration {
        self.slot_duration() / INTERVALS_PER_SLOT as u32
    }

    /// Returns the delay between the start of the slot and when sync committee messages should be
    /// produced.
    fn sync_committee_message_production_delay(&self) -> Duration {
        self.slot_duration() / INTERVALS_PER_SLOT as u32
    }

    /// Returns the delay between the start of the slot and when aggregated attestations should be
    /// produced.
    fn agg_attestation_production_delay(&self) -> Duration {
        self.slot_duration() * 2 / INTERVALS_PER_SLOT as u32
    }

    /// Returns the delay between the start of the slot and when partially aggregated `SyncCommitteeContribution` should be
    /// produced.
    fn sync_committee_contribution_production_delay(&self) -> Duration {
        self.slot_duration() * 2 / INTERVALS_PER_SLOT as u32
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
