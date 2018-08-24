use super::super::utils::types::Hash256;

pub mod attestation_parent_hashes;

#[derive(Debug)]
pub enum TransitionError {
    IntWrapping,
    OutOfBounds,
    InvalidInput(String),
}



