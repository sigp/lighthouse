#[macro_use]
extern crate lazy_static;

mod metrics;
mod system_time_slot_clock;
mod testing_slot_clock;

use std::time::Duration;

pub use crate::system_time_slot_clock::SystemTimeSlotClock;
pub use crate::testing_slot_clock::TestingSlotClock;
pub use metrics::scrape_for_metrics;
pub use types::Slot;

/// A clock that reports the current slot.
///
/// The clock is not required to be monotonically increasing and may go backwards.
pub trait SlotClock: Send + Sync + Sized {
    /// Creates a new slot clock where the first slot is `genesis_slot`, genesis occured
    /// `genesis_duration` after the `UNIX_EPOCH` and each slot is `slot_duration` apart.
    fn new(genesis_slot: Slot, genesis_duration: Duration, slot_duration: Duration) -> Self;

    /// Returns the slot at this present time.
    fn now(&self) -> Option<Slot>;

    /// Returns the duration between slots
    fn slot_duration(&self) -> Duration;

    /// Returns the duration until the next slot.
    fn duration_to_next_slot(&self) -> Option<Duration>;
}
