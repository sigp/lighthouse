use crate::{beacon_chain::BeaconForkChoice, BeaconChainTypes, BeaconSnapshot};
use fork_choice::{ExecutionStatus, ForkChoiceView};
use types::*;

pub struct CanonicalHead<T: BeaconChainTypes> {
    /// Provides an in-memory representation of the non-finalized block tree and is used to run the
    /// fork choice algorithm and determine the canonical head.
    pub fork_choice: BeaconForkChoice<T>,
    /// The view of the LMD head and FFG checkpoints, cached from the last time the head was
    /// updated.
    pub fork_choice_view: ForkChoiceView,
    /// Provides the head block and state from the last time the head was updated.
    pub head_snapshot: BeaconSnapshot<T::EthSpec>,
    /// This value is pre-computed to make life simpler for downstream users.
    pub head_proposer_shuffling_decision_root: Hash256,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChainSummary {
    pub head_slot: Slot,
    pub head_block_root: Hash256,
    pub head_state_root: Hash256,
    pub head_proposer_shuffling_decision_root: Hash256,
    pub head_execution_status: ExecutionStatus,
    pub head_fork: Fork,
    pub head_random: Hash256,
    pub justified_checkpoint: types::Checkpoint,
    pub finalized_checkpoint: types::Checkpoint,
    pub genesis_time: u64,
    pub genesis_validators_root: Hash256,
    pub is_merge_transition_complete: bool,
}

impl<T: BeaconChainTypes> CanonicalHead<T> {
    /// Returns root of the block at the head of the beacon chain.
    pub fn head_root(&self) -> Hash256 {
        self.head_snapshot.beacon_block_root
    }

    /// Returns root of the `BeaconState` at the head of the beacon chain.
    ///
    /// ## Note
    ///
    /// This `BeaconState` has *not* been advanced to the current slot, it has the same slot as the
    /// head block.
    pub fn head_state_root(&self) -> Hash256 {
        self.head_snapshot.beacon_state_root()
    }

    /// Returns slot of the block at the head of the beacon chain.
    ///
    /// ## Notes
    ///
    /// This is *not* the current slot as per the system clock.
    pub fn head_slot(&self) -> Slot {
        self.head_snapshot.beacon_block.slot()
    }

    /// Returns the slot and root of the block at the head of the beacon chain.
    pub fn head_slot_and_root(&self) -> (Slot, Hash256) {
        (self.head_slot(), self.head_root())
    }

    /// Returns the `Fork` from the `BeaconState` at the head of the chain.
    pub fn head_fork(&self) -> Fork {
        self.head_snapshot.beacon_state.fork()
    }

    /// Returns the execution status of the block at the head of the beacon chain.
    ///
    /// ## Notes
    ///
    ///
    pub fn head_execution_status(&self) -> Option<ExecutionStatus> {
        self.fork_choice
            .get_block_execution_status(&self.head_root())
    }

    /// Returns the randao mix for the block at the head of the chain.
    pub fn head_random(&self) -> Result<Hash256, BeaconStateError> {
        let state = &self.head_snapshot.beacon_state;
        state.get_randao_mix(state.current_epoch()).copied()
    }

    pub fn finalized_checkpoint(&self) -> Checkpoint {
        self.fork_choice_view.finalized_checkpoint
    }

    pub fn justified_checkpoint(&self) -> Checkpoint {
        self.fork_choice_view.finalized_checkpoint
    }

    pub fn genesis_time(&self) -> u64 {
        self.head_snapshot.beacon_state.genesis_time()
    }

    /*
    /// Returns info representing the head block and the state of the beacon chain.
    ///
    /// Can be used as a summarized version of `self.head_snapshot` that involves less cloning.
    ///
    /// ## Notes
    ///
    /// This method replaces the `BeaconChain::head_info` method. The `head_info` method was
    /// deprecated since it provided the finalized/justified checkpoints of the *head block*,
    /// rather than that of fork choice. It is important to use the values from fork choice since
    /// it's possible that the finalized/justified values read from the head block state can go
    /// "backwards" due to unrealized votes.
    pub fn chain_summary(&self) -> ChainSummary {
        let head = &self.head_snapshot;
        let (head_slot, head_block_root) = self.head_slot_and_root();
        let head_block = head.beacon_block.message();
        let head_state = &head.beacon_state;
        let head_execution_status = self
            .fork_choice
            .get_block_execution_status(&head.beacon_block_root)
            .unwrap_or_else(|| {
                // Use the execution status from when the block was set as the head. Using this
                // backup ensures this function does not need to return a `Result`.
                self.head_execution_status
            });

        ChainSummary {
            head_slot,
            head_block_root,
            head_state_root: head.beacon_block.state_root(),
            head_proposer_shuffling_decision_root: self.head_proposer_shuffling_decision_root,
            head_execution_status,
            head_fork: self.head_fork(),
            head_random: self.head_random,
            justified_checkpoint: self.fork_choice_view.justified_checkpoint,
            finalized_checkpoint: self.fork_choice_view.finalized_checkpoint,
            genesis_time: self.genesis_duration,
            genesis_validators_root: self.genesis_validators_root,
            is_merge_transition_complete: head_block
                .body()
                .execution_payload()
                .map_or(false, |ep| ep.block_hash() != <_>::default()),
        }
    }
    */
}
