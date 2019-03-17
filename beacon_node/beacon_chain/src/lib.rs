mod attestation_aggregator;
mod beacon_chain;
mod checkpoint;
mod errors;

pub use self::beacon_chain::{BeaconChain, BlockProcessingOutcome, InvalidBlock, ValidBlock};
pub use self::checkpoint::CheckPoint;
pub use self::errors::BeaconChainError;
pub use fork_choice::{ForkChoice, ForkChoiceAlgorithm, ForkChoiceError};
