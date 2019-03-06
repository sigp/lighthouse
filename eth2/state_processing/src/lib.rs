#[macro_use]
mod macros;

pub mod per_block_processing;
pub mod per_epoch_processing;
// mod slot_processable;

pub use per_block_processing::{
    errors::{BlockInvalid, BlockProcessingError},
    per_block_processing, per_block_processing_without_verifying_block_signature,
};
pub use per_epoch_processing::{errors::EpochProcessingError, per_epoch_processing};
// pub use epoch_processable::{EpochProcessable, Error as EpochProcessingError};
// pub use slot_processable::{Error as SlotProcessingError, SlotProcessable};
