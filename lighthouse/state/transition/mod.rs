use super::super::utils::types::Hash256;
use super::crystallized_state;
use super::super::db;
use super::ssz;
use super::blake2;
use super::utils;

mod attestation_parent_hashes;
mod shuffling;
mod validate_block;

pub use self::attestation_parent_hashes::attestation_parent_hashes;
pub use self::shuffling::shuffle;

#[derive(Debug)]
pub enum TransitionError {
    IntWrapping,
    OutOfBounds,
    InvalidInput(String),
}



