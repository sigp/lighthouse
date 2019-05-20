//! This crate stores the various implementations of fork-choice rules that can be used for the
//! beacon blockchain.
//!
//! There are three implementations. One is the naive longest chain rule (primarily for testing
//! purposes). The other two are proposed implementations of the LMD-GHOST fork-choice rule with various forms of optimisation.
//!
//! The current implementations are:
//! - [`longest-chain`]: Simplistic longest-chain fork choice - primarily for testing, **not for
//! production**.
//! - [`slow_lmd_ghost`]: This is a simple and very inefficient implementation given in the ethereum 2.0
//! specifications (https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#get_block_root).
//! - [`bitwise_lmd_ghost`]: This is an optimised version of bitwise LMD-GHOST as proposed
//! by Vitalik. The reference implementation can be found at: https://github.com/ethereum/research/blob/master/ghost/ghost.py
//!
//! [`longest-chain`]: struct.LongestChain.html
//! [`slow_lmd_ghost`]: struct.SlowLmdGhost.html
//! [`bitwise_lmd_ghost`]: struct.OptimisedLmdGhost.html

/*
pub mod bitwise_lmd_ghost;
pub mod longest_chain;
pub mod optimized_lmd_ghost;
*/
pub mod slow_lmd_ghost;

// use db::stores::BeaconBlockAtSlotError;
// use db::DBError;
use db::Error as DBError;
use types::{BeaconBlock, ChainSpec, Hash256};

/*
pub use bitwise_lmd_ghost::BitwiseLMDGhost;
pub use longest_chain::LongestChain;
pub use optimized_lmd_ghost::OptimizedLMDGhost;
*/
pub use slow_lmd_ghost::SlowLMDGhost;

/// Defines the interface for Fork Choices. Each Fork choice will define their own data structures
/// which can be built in block processing through the `add_block` and `add_attestation` functions.
/// The main fork choice algorithm is specified in `find_head
pub trait ForkChoice: Send + Sync {
    /// Called when a block has been added. Allows generic block-level data structures to be
    /// built for a given fork-choice.
    fn add_block(
        &mut self,
        block: &BeaconBlock,
        block_hash: &Hash256,
        spec: &ChainSpec,
    ) -> Result<(), ForkChoiceError>;
    /// Called when an attestation has been added. Allows generic attestation-level data structures to be built for a given fork choice.
    // This can be generalised to a full attestation if required later.
    fn add_attestation(
        &mut self,
        validator_index: u64,
        target_block_hash: &Hash256,
        spec: &ChainSpec,
    ) -> Result<(), ForkChoiceError>;
    /// The fork-choice algorithm to find the current canonical head of the chain.
    // TODO: Remove the justified_start_block parameter and make it internal
    fn find_head(
        &mut self,
        justified_start_block: &Hash256,
        spec: &ChainSpec,
    ) -> Result<Hash256, ForkChoiceError>;
}

/// Possible fork choice errors that can occur.
#[derive(Debug, PartialEq)]
pub enum ForkChoiceError {
    MissingBeaconBlock(Hash256),
    MissingBeaconState(Hash256),
    IncorrectBeaconState(Hash256),
    CannotFindBestChild,
    ChildrenNotFound,
    StorageError(String),
    HeadNotFound,
}

impl From<DBError> for ForkChoiceError {
    fn from(e: DBError) -> ForkChoiceError {
        ForkChoiceError::StorageError(format!("{:?}", e))
    }
}

/*
impl From<BeaconBlockAtSlotError> for ForkChoiceError {
    fn from(e: BeaconBlockAtSlotError) -> ForkChoiceError {
        match e {
            BeaconBlockAtSlotError::UnknownBeaconBlock(hash) => {
                ForkChoiceError::MissingBeaconBlock(hash)
            }
            BeaconBlockAtSlotError::InvalidBeaconBlock(hash) => {
                ForkChoiceError::MissingBeaconBlock(hash)
            }
            BeaconBlockAtSlotError::DBError(string) => ForkChoiceError::StorageError(string),
        }
    }
}
*/

/// Fork choice options that are currently implemented.
#[derive(Debug, Clone)]
pub enum ForkChoiceAlgorithm {
    /// Chooses the longest chain becomes the head. Not for production.
    LongestChain,
    /// A simple and highly inefficient implementation of LMD ghost.
    SlowLMDGhost,
    /// An optimised version of bitwise LMD-GHOST by Vitalik.
    BitwiseLMDGhost,
    /// An optimised implementation of LMD ghost.
    OptimizedLMDGhost,
}
