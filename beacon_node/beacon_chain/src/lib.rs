#![recursion_limit = "128"] // For lazy-static
#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate slog;
extern crate slog_term;

pub mod attestation_verification;
mod beacon_chain;
mod beacon_fork_choice_store;
mod beacon_snapshot;
mod block_verification;
pub mod builder;
pub mod chain_config;
mod errors;
pub mod eth1_chain;
pub mod events;
mod head_tracker;
mod metrics;
pub mod migrate;
mod naive_aggregation_pool;
mod observed_attestations;
mod observed_attesters;
mod observed_block_producers;
pub mod observed_operations;
mod persisted_beacon_chain;
mod persisted_fork_choice;
mod shuffling_cache;
mod snapshot_cache;
pub mod test_utils;
mod timeout_rw_lock;
mod validator_pubkey_cache;

pub use self::beacon_chain::{
    AttestationProcessingOutcome, BeaconChain, BeaconChainTypes, ChainSegmentResult,
    ForkChoiceError, StateSkipConfig,
};
pub use self::beacon_snapshot::BeaconSnapshot;
pub use self::chain_config::ChainConfig;
pub use self::errors::{BeaconChainError, BlockProductionError};
pub use attestation_verification::Error as AttestationError;
pub use beacon_fork_choice_store::{BeaconForkChoiceStore, Error as ForkChoiceStoreError};
pub use block_verification::{BlockError, GossipVerifiedBlock};
pub use eth1_chain::{Eth1Chain, Eth1ChainBackend};
pub use events::EventHandler;
pub use metrics::scrape_for_metrics;
pub use parking_lot;
pub use slot_clock;
pub use state_processing::per_block_processing::errors::{
    AttestationValidationError, AttesterSlashingValidationError, DepositValidationError,
    ExitValidationError, ProposerSlashingValidationError,
};
pub use store;
pub use types;
