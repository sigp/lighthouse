#![deny(clippy::integer_arithmetic)]
#![deny(clippy::disallowed_method)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::let_underscore_must_use)]

#[macro_use]
mod macros;

pub mod common;
pub mod genesis;
pub mod per_block_processing;
pub mod per_epoch_processing;
pub mod per_slot_processing;
pub mod state_advance;
pub mod verify_operation;

pub use genesis::{
    eth2_genesis_time, initialize_beacon_state_from_eth1, is_valid_genesis_state,
    process_activations,
};
pub use per_block_processing::{
    block_signature_verifier, errors::BlockProcessingError, per_block_processing, signature_sets,
    BlockSignatureStrategy, BlockSignatureVerifier, VerifySignatures,
};
pub use per_epoch_processing::{
    errors::EpochProcessingError, process_epoch as per_epoch_processing,
};
pub use per_slot_processing::{per_slot_processing, Error as SlotProcessingError};
pub use verify_operation::{SigVerifiedOp, VerifyOperation};
