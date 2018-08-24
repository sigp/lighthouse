use super::super::utils::types::Hash256;

mod attestation_parent_hashes;

pub use self::attestation_parent_hashes::attestation_parent_hashes;

#[derive(Debug)]
pub enum TransitionError {
    IntWrapping,
    OutOfBounds,
    InvalidInput(String),
}



