#[macro_use]
extern crate lazy_static;

mod manual_slot_clock;
mod metrics;
mod system_time_slot_clock;

use std::time::Duration;

pub use crate::manual_slot_clock::ManualSlotClock;
pub use crate::manual_slot_clock::ManualSlotClock as TestingSlotClock;
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

    /// Returns the duration until the first slot of the next epoch.
    fn duration_to_next_epoch(&self, slots_per_epoch: u64) -> Option<Duration>;

    /// Returns the start time of the slot, as a duration since `UNIX_EPOCH`.
    fn start_of(&self, slot: Slot) -> Option<Duration>;

    /// Returns the first slot to be returned at the genesis time.
    fn genesis_slot(&self) -> Slot;

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
        self.slot_duration() / 3
    }

    /// Returns the delay between the start of the slot and when sync committee messages should be
    /// produced.
    fn sync_committee_message_production_delay(&self) -> Duration {
        self.slot_duration() / 3
    }

    /// Returns the delay between the start of the slot and when aggregated attestations should be
    /// produced.
    fn agg_attestation_production_delay(&self) -> Duration {
        self.slot_duration() * 2 / 3
    }

    /// Returns the delay between the start of the slot and when partially aggregated `SyncCommitteeContribution` should be
    /// produced.
    fn sync_committee_contribution_production_delay(&self) -> Duration {
        self.slot_duration() * 2 / 3
    }
}
