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
use std::convert::TryInto;
pub use types::Slot;

/// A clock that reports the current slot.
///
/// The clock is not required to be monotonically increasing and may go backwards.
pub trait SlotClock: Send + Sync + Sized {
    /// Creates a new slot clock where the first slot is `genesis_slot`, genesis occurred
    /// `genesis_duration` after the `UNIX_EPOCH` and each slot is `slot_duration` apart.
    fn new(genesis_slot: Slot, genesis_duration: Duration, slot_duration: Duration) -> Self;

    /// Returns the slot at this present time.
    fn now(&self) -> Option<Slot>;

    /// Returns the present time as a duration since the UNIX epoch.
    ///
    /// Returns `None` if the present time is before the UNIX epoch (unlikely).
    fn now_duration(&self) -> Option<Duration>;

    /// Returns the slot of the given duration since the UNIX epoch.
    fn slot_of(&self, now: Duration) -> Option<Slot>;

    /// Returns the duration between slots
    fn slot_duration(&self) -> Duration;

    /// Returns the duration until the next slot.
    fn duration_to_next_slot(&self) -> Option<Duration>;

    /// Returns the duration until the first slot of the next epoch.
    fn duration_to_next_epoch(&self, slots_per_epoch: u64) -> Option<Duration>;

    /// Returns the duration between UNIX epoch and the start of the 0'th slot.
    fn genesis_slot(&self) -> Slot;

    /// Returns the duration between UNIX epoch and the start of the genesis slot.
    fn genesis_duration(&self) -> Duration;

    /// Indicates if the slot now is within (inclusive) the given `low_slot`
    /// and `high_slot`, accounting for a `tolerance` on either side of the
    /// range.
    ///
    /// Returns `None` if:
    ///
    /// - The current slot is unknown.
    /// - `low_slot > high_slot`
    /// - The `high_slot` or `low_slot` are unable to be converted into a `u32`.
    /// - The `high_slot` or `low_slot` are lower than `self.genesis_slot()`.
    /// - There is an integer overflow during evaluation.
    fn now_is_within(&self, low_slot: Slot, high_slot: Slot, tolerance: Duration) -> Option<bool> {
        if low_slot > high_slot {
            return None;
        }

        let to_duration = |slot: Slot| -> Option<Duration> {
            let slot = Slot::from(slot.as_u64().checked_sub(self.genesis_slot().as_u64())?);
            let raw_duration = self
                .slot_duration()
                .checked_mul(slot.as_u64().try_into().ok()?)?;
            raw_duration.checked_add(self.genesis_duration())
        };

        let high = to_duration(high_slot)?.checked_add(self.slot_duration())?;
        let low = to_duration(low_slot)?;
        let now = self.now_duration()?;

        Some(low <= now.checked_add(tolerance)? && now < high.checked_add(tolerance)?)
    }
}
