//! Provides a testing environment for the `BeaconChain`, `Attester` and `BlockProposer` objects.
//!
//! This environment bypasses networking client runtimes and connects the `Attester` and `Proposer`
//! directly to the `BeaconChain` via an `Arc`.
//!
//! The `BeaconChainHarness` contains a single `BeaconChain` instance and many `ValidatorHarness`
//! instances. All of the `ValidatorHarness` instances work to advance the `BeaconChain` by
//! producing blocks and attestations.
//!
//! Example:
//! ```
//! use test_harness::BeaconChainHarness;
//! use types::ChainSpec;
//!
//! let validator_count = 8;
//! let spec = ChainSpec::few_validators();
//!
//! let mut harness = BeaconChainHarness::new(spec, validator_count);
//!
//! harness.advance_chain_with_block();
//!
//! let chain = harness.chain_dump().unwrap();
//!
//! // One block should have been built on top of the genesis block.
//! assert_eq!(chain.len(), 2);
//! ```

mod beacon_chain_harness;
pub mod test_case;
mod validator_harness;

pub use self::beacon_chain_harness::BeaconChainHarness;
pub use self::validator_harness::ValidatorHarness;
