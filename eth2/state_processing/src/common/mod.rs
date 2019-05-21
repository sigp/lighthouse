mod exit;
mod get_attesting_indices;
mod slash_validator;
mod verify_bitfield;

pub use exit::initiate_validator_exit;
pub use get_attesting_indices::{get_attesting_indices, get_attesting_indices_unsorted};
pub use slash_validator::slash_validator;
pub use verify_bitfield::verify_bitfield_length;
