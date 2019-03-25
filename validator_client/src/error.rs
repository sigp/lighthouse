use slot_clock;

use error_chain::{
    error_chain, error_chain_processing, impl_error_chain_kind, impl_error_chain_processed,
    impl_extract_backtrace,
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
