use super::utils::types::Hash256;
use super::db;

mod attestation_parent_hashes;
mod shuffling;

pub use self::attestation_parent_hashes::attestation_parent_hashes;
pub use self::shuffling::shuffle;

#[derive(Debug)]
pub enum TransitionError {
    IntWrapping,
    OutOfBounds,
    InvalidInput(String),
}



