mod attestation_aggregator;
mod beacon_chain;
mod checkpoint;

pub use self::beacon_chain::{
    BeaconChain, BlockProcessingOutcome, Error, InvalidBlock, ValidBlock,
};
pub use self::checkpoint::CheckPoint;
pub use fork_choice::{ForkChoice, ForkChoiceAlgorithms, ForkChoiceError};
