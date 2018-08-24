use super::super::utils::types::Hash256;

pub mod helpers;

#[derive(Debug)]
pub enum TransitionError {
    IntWrapping,
    OutOfBounds,
    InvalidInput(String),
}

