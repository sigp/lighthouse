pub mod reduced_tree;

use std::sync::Arc;
use types::{Hash256, Slot};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    BackendError(String),
}

pub trait LmdGhostBackend<T>: Send + Sync {
    fn new(store: Arc<T>) -> Self;

    fn process_message(
        &self,
        validator_index: usize,
        block_hash: Hash256,
        block_slot: Slot,
    ) -> Result<()>;

    fn find_head(&self) -> Result<Hash256>;
}

pub struct ForkChoice<T> {
    algorithm: T,
}

impl<T: LmdGhostBackend<T>> ForkChoice<T> {
    pub fn new(store: Arc<T>) -> Self {
        Self {
            algorithm: T::new(store),
        }
    }
}
