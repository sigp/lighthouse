use beacon_chain::{BeaconChain, BeaconChainTypes};
use types::{EthSpec, Hash256};

use lighthouse_network::rpc::StatusMessage;
/// Trait to produce a `StatusMessage` representing the state of the given `beacon_chain`.
///
/// NOTE: The purpose of this is simply to obtain a `StatusMessage` from the `BeaconChain` without
/// polluting/coupling the type with RPC concepts.
pub trait ToStatusMessage {
    fn status_message(&self) -> StatusMessage;
}

impl<T: BeaconChainTypes> ToStatusMessage for BeaconChain<T> {
    fn status_message(&self) -> StatusMessage {
        status_message(self)
    }
}

/// Build a `StatusMessage` representing the state of the given `beacon_chain`.
pub(crate) fn status_message<T: BeaconChainTypes>(beacon_chain: &BeaconChain<T>) -> StatusMessage {
    let fork_digest = [0x9c, 0x67, 0x11, 0x28];
    let cached_head = beacon_chain.canonical_head.cached_head();
    let mut finalized_checkpoint = cached_head.finalized_checkpoint();

    // Alias the genesis checkpoint root to `0x00`.
    let spec = &beacon_chain.spec;
    let genesis_epoch = spec.genesis_slot.epoch(T::EthSpec::slots_per_epoch());
    if finalized_checkpoint.epoch == genesis_epoch {
        finalized_checkpoint.root = Hash256::zero();
    }

    StatusMessage {
        fork_digest,
        finalized_root: finalized_checkpoint.root,
        finalized_epoch: finalized_checkpoint.epoch,
        head_root: cached_head.head_block_root(),
        head_slot: cached_head.head_slot(),
    }
}
