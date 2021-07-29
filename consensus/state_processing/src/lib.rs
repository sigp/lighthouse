// Clippy lint set-up (disabled in tests)
#![cfg_attr(
    not(test),
    deny(
        clippy::integer_arithmetic,
        clippy::disallowed_method,
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::let_underscore_must_use
    )
)]

#[macro_use]
mod macros;
mod metrics;

pub mod common;
pub mod genesis;
pub mod per_block_processing;
pub mod per_epoch_processing;
pub mod per_slot_processing;
pub mod state_advance;
pub mod upgrade;
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
