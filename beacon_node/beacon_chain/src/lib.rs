#![recursion_limit = "128"] // For lazy-static
#[macro_use]
extern crate lazy_static;

mod beacon_chain;
mod beacon_chain_builder;
mod checkpoint;
mod errors;
mod eth1_chain;
pub mod events;
mod fork_choice;
mod iter;
mod metrics;
mod persisted_beacon_chain;
pub mod test_utils;

pub use self::beacon_chain::{
    AttestationProcessingOutcome, BeaconChain, BeaconChainTypes, BlockProcessingOutcome,
};
pub use self::checkpoint::CheckPoint;
pub use self::errors::{BeaconChainError, BlockProductionError};
pub use beacon_chain_builder::BeaconChainBuilder;
pub use eth1_chain::{Eth1ChainBackend, InteropEth1ChainBackend};
pub use lmd_ghost;
pub use metrics::scrape_for_metrics;
pub use parking_lot;
pub use slot_clock;
pub use state_processing::per_block_processing::errors::{
    AttestationValidationError, AttesterSlashingValidationError, DepositValidationError,
    ExitValidationError, ProposerSlashingValidationError, TransferValidationError,
};
pub use store;
pub use types;
