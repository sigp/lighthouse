#[macro_use]
mod macros;

pub mod per_block_processing;
pub mod per_epoch_processing;
pub mod per_slot_processing;

pub use per_block_processing::{
    errors::{BlockInvalid, BlockProcessingError},
    per_block_processing, per_block_processing_without_verifying_block_signature,
};
pub use per_epoch_processing::{errors::EpochProcessingError, per_epoch_processing};
pub use per_slot_processing::{per_slot_processing, Error as SlotProcessingError};
