use slot_clock;

use error_chain::{
    error_chain
};

error_chain! {
   links  { }

   errors {
    SlotClockError(e: slot_clock::SystemTimeSlotClockError) {
        description("Error reading system time"),
        display("SlotClockError: '{:?}'", e)
    }

    SystemTimeError(t: String ) {
        description("Error reading system time"),
        display("SystemTimeError: '{}'", t)
    }
   }
}
