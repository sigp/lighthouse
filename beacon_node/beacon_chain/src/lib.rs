#![recursion_limit = "128"] // For lazy-static
#[macro_use]
extern crate lazy_static;

mod beacon_chain;
mod beacon_snapshot;
pub mod builder;
mod errors;
pub mod eth1_chain;
pub mod events;
mod fork_choice;
mod head_tracker;
mod metrics;
mod persisted_beacon_chain;
mod shuffling_cache;
mod snapshot_cache;
pub mod test_utils;
mod timeout_rw_lock;
mod validator_pubkey_cache;

pub use self::beacon_chain::{
    AttestationProcessingOutcome, BeaconChain, BeaconChainTypes, BlockProcessingOutcome,
    StateSkipConfig,
};
pub use self::beacon_snapshot::BeaconSnapshot;
pub use self::errors::{BeaconChainError, BlockProductionError};
pub use eth1_chain::{Eth1Chain, Eth1ChainBackend};
pub use events::EventHandler;
pub use fork_choice::ForkChoice;
pub use metrics::scrape_for_metrics;
pub use parking_lot;
pub use slot_clock;
pub use state_processing::per_block_processing::errors::{
    AttestationValidationError, AttesterSlashingValidationError, DepositValidationError,
    ExitValidationError, ProposerSlashingValidationError,
};
pub use store;
pub use types;
