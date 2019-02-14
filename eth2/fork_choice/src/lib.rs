// Copyright 2019 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! This crate stores the various implementations of fork-choice rules that can be used for the
//! beacon blockchain.
//!
//! There are four implementations. One is the naive longest chain rule (primarily for testing
//! purposes). The other three are proposed implementations of the LMD-GHOST fork-choice rule with various forms of optimisation.
//!
//! The current implementations are:
//! - [`longest-chain`]: Simplistic longest-chain fork choice - primarily for testing, **not for
//! production**.
//! - [`slow_lmd_ghost`]: This is a simple and very inefficient implementation given in the ethereum 2.0
//! specifications (https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#get_block_root).
//! - [`optimised_lmd_ghost`]: This is an optimised version of the naive implementation as proposed
//! by Vitalik. The reference implementation can be found at: https://github.com/ethereum/research/blob/master/ghost/ghost.py
//! - [`protolambda_lmd_ghost`]: Another optimised version of LMD-GHOST designed by @protolambda.
//! The go implementation can be found here: https://github.com/protolambda/lmd-ghost.
//!
//! [`slow_lmd_ghost`]: struct.SlowLmdGhost.html
//! [`optimised_lmd_ghost`]: struct.OptimisedLmdGhost.html
//! [`protolambda_lmd_ghost`]: struct.ProtolambdaLmdGhost.html

extern crate db;
extern crate ssz;
extern crate types;

pub mod longest_chain;
pub mod optimised_lmd_ghost;
//pub mod protolambda_lmd_ghost;
pub mod slow_lmd_ghost;

use db::stores::BeaconBlockAtSlotError;
use db::DBError;
use types::{BeaconBlock, Hash256};

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
    ) -> Result<(), ForkChoiceError>;
    /// Called when an attestation has been added. Allows generic attestation-level data structures to be built for a given fork choice.
    // This can be generalised to a full attestation if required later.
    fn add_attestation(
        &mut self,
        validator_index: u64,
        target_block_hash: &Hash256,
    ) -> Result<(), ForkChoiceError>;
    /// The fork-choice algorithm to find the current canonical head of the chain.
    // TODO: Remove the justified_start_block parameter and make it internal
    fn find_head(&mut self, justified_start_block: &Hash256) -> Result<Hash256, ForkChoiceError>;
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
        ForkChoiceError::StorageError(e.message)
    }
}

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

/// Fork choice options that are currently implemented.
pub enum ForkChoiceAlgorithms {
    /// Chooses the longest chain becomes the head. Not for production.
    LongestChain,
    /// A simple and highly inefficient implementation of LMD ghost.
    SlowLMDGhost,
    /// An optimised version of LMD-GHOST by Vitalik.
    OptimisedLMDGhost,
    // Protolambda currently not implemented
    // /// An optimised version of LMD-GHOST by Protolambda.
    //ProtoLMDGhost,
}
