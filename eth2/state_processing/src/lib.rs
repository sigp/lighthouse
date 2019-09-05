#[macro_use]
mod macros;

pub mod common;
pub mod genesis;
pub mod per_block_processing;
pub mod per_epoch_processing;
pub mod per_slot_processing;
pub mod test_utils;

pub use genesis::{initialize_beacon_state_from_eth1, is_valid_genesis_state};
pub use per_block_processing::{
    errors::BlockProcessingError, per_block_processing, BlockSignatureStrategy, VerifySignatures,
};
pub use per_epoch_processing::{errors::EpochProcessingError, per_epoch_processing};
pub use per_slot_processing::{per_slot_processing, Error as SlotProcessingError};
