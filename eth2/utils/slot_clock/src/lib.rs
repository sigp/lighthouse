mod system_time_slot_clock;
mod testing_slot_clock;

pub use crate::system_time_slot_clock::{Error as SystemTimeSlotClockError, SystemTimeSlotClock};
pub use crate::testing_slot_clock::{Error as TestingSlotClockError, TestingSlotClock};

pub trait SlotClock: Send + Sync {
    type Error;

    fn present_slot(&self) -> Result<Option<u64>, Self::Error>;
}
