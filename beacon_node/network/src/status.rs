use beacon_chain::{BeaconChain, BeaconChainTypes};

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
        let chain_summary = self.chain_summary();
        let fork_digest = self.enr_fork_id().fork_digest;

        StatusMessage {
            fork_digest,
            finalized_root: chain_summary.finalized_checkpoint.root,
            finalized_epoch: chain_summary.finalized_checkpoint.epoch,
            head_root: chain_summary.head_block_root,
            head_slot: chain_summary.head_slot,
        }
    }
}
