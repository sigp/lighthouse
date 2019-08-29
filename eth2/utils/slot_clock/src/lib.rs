#[macro_use]
extern crate lazy_static;

mod metrics;
mod system_time_slot_clock;
mod testing_slot_clock;

use std::time::{Duration, Instant};

pub use crate::system_time_slot_clock::SystemTimeSlotClock;
pub use crate::testing_slot_clock::TestingSlotClock;
pub use metrics::scrape_for_metrics;
pub use types::Slot;

pub trait SlotClock: Send + Sync + Sized {
    fn new(genesis_slot: Slot, genesis: Instant, slot_duration: Duration) -> Self;

    fn present_slot(&self) -> Option<Slot>;

    fn duration_to_next_slot(&self) -> Option<Duration>;

    fn slot_duration(&self) -> Duration;
}
