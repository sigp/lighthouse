// Clippy lint set-up (disabled in tests)
#![cfg_attr(
    not(test),
    deny(
        clippy::arithmetic_side_effects,
        clippy::disallowed_methods,
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

pub mod all_caches;
pub mod block_replayer;
pub mod common;
pub mod consensus_context;
pub mod epoch_cache;
pub mod execution_processing;
pub mod genesis;
pub mod per_block_processing;
pub mod per_epoch_processing;
pub mod per_slot_processing;
pub mod state_advance;
pub mod upgrade;
pub mod verify_operation;

pub use all_caches::AllCaches;
pub use block_replayer::{BlockReplayError, BlockReplayer};
pub use consensus_context::{ConsensusContext, ContextError};
pub use execution_processing::process_execution_payload_envelope;
pub use genesis::{
    eth2_genesis_time, initialize_beacon_state_from_eth1, is_valid_genesis_state,
    process_activations,
};
pub use per_block_processing::{
    block_signature_verifier, errors::BlockProcessingError, per_block_processing, signature_sets,
    BlockSignatureStrategy, BlockSignatureVerifier, VerifyBlockRoot, VerifySignatures,
};
pub use per_epoch_processing::{
    errors::EpochProcessingError, process_epoch as per_epoch_processing,
};
pub use per_slot_processing::{per_slot_processing, Error as SlotProcessingError};
pub use types::{EpochCache, EpochCacheError, EpochCacheKey};
pub use verify_operation::{SigVerifiedOp, TransformPersist, VerifyOperation, VerifyOperationAt};
