use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2_libp2p::rpc::StatusMessage;
use types::ChainSpec;

pub trait ToStatusMessage {
    fn status_message(&self) -> Result<StatusMessage, BeaconChainError>;
}

impl<T: BeaconChainTypes> ToStatusMessage for BeaconChain<T> {
    fn status_message(&self) -> Result<StatusMessage, BeaconChainError> {
        let head_info = self.head_info()?;
        let genesis_validators_root = self.genesis_validators_root;

        let fork_digest =
            ChainSpec::compute_fork_digest(head_info.fork.current_version, genesis_validators_root);

        Ok(StatusMessage {
            fork_digest,
            finalized_root: head_info.finalized_checkpoint.root,
            finalized_epoch: head_info.finalized_checkpoint.epoch,
            head_root: head_info.block_root,
            head_slot: head_info.slot,
        })
    }
}
