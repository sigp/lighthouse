mod system_time_slot_clock;
mod testing_slot_clock;

pub use crate::system_time_slot_clock::{Error as SystemTimeSlotClockError, SystemTimeSlotClock};
pub use crate::testing_slot_clock::{Error as TestingSlotClockError, TestingSlotClock};
use std::time::Duration;
pub use types::Slot;

pub trait SlotClock: Send + Sync {
    type Error;

    fn present_slot(&self) -> Result<Option<Slot>, Self::Error>;

    fn duration_to_next_slot(&self) -> Result<Option<Duration>, Self::Error>;
}
