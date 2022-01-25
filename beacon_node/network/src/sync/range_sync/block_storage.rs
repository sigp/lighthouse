use beacon_chain::{BeaconChain, BeaconChainTypes};
use types::Hash256;

/// Trait that helps maintain RangeSync's implementation split from the BeaconChain
pub trait BlockStorage {
    fn is_block_known(&self, block_root: &Hash256) -> bool;
}

impl<T: BeaconChainTypes> BlockStorage for BeaconChain<T> {
    fn is_block_known(&self, block_root: &Hash256) -> bool {
        self.fork_choice.read().contains_block(block_root)
    }
}
