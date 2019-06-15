mod reduced_tree;

use std::sync::Arc;
use store::Store;
use types::{EthSpec, Hash256, Slot};

pub use reduced_tree::ThreadSafeReducedTree;

pub type Result<T> = std::result::Result<T, String>;

pub trait LmdGhost<S: Store, E: EthSpec>: Send + Sync {
    fn new(store: Arc<S>) -> Self;

    fn process_message(
        &self,
        validator_index: usize,
        block_hash: Hash256,
        block_slot: Slot,
    ) -> Result<()>;

    fn find_head(&self) -> Result<Hash256>;
}
