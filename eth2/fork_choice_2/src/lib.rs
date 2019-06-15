pub mod reduced_tree;

use std::sync::Arc;
use store::Error as DBError;
use store::Store;
use types::{BeaconBlock, ChainSpec, Hash256, Slot};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    BackendError(String),
}

pub trait LmdGhostBackend<T> {
    fn new(store: Arc<T>) -> Self;

    fn process_message(
        &mut self,
        validator_index: usize,
        block_hash: Hash256,
        block_slot: Slot,
    ) -> Result<()>;

    fn find_head(&mut self) -> Result<Hash256>;
}

pub struct ForkChoice<T> {
    algorithm: T,
}

impl<T: LmdGhostBackend<T>> ForkChoice<T> {
    fn new(store: Arc<T>) -> Self {
        Self {
            algorithm: T::new(store),
        }
    }
}
