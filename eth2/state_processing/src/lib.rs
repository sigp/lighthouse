#[macro_use]
mod macros;
mod block_processable;
// mod epoch_processable;
mod errors;
// mod slot_processable;

pub use block_processable::{
    validate_attestation, validate_attestation_without_signature, BlockProcessable,
    Error as BlockProcessingError,
};
// pub use epoch_processable::{EpochProcessable, Error as EpochProcessingError};
// pub use slot_processable::{Error as SlotProcessingError, SlotProcessable};
