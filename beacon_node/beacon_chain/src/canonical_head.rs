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

impl<T: BeaconChainTypes> CanonicalHead<T> {
    /// Returns root of the block at the head of the beacon chain.
    pub fn head_block_root(&self) -> Hash256 {
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
            .get_block_execution_status(&self.head_block_root())
    }

    /// Returns the randao mix for the block at the head of the chain.
    pub fn head_random(&self) -> Result<Hash256, BeaconStateError> {
        let state = &self.head_snapshot.beacon_state;
        state.get_randao_mix(state.current_epoch()).copied()
    }

    /// Returns the finalized checkpoint, as determined by fork choice.
    ///
    /// ## Note
    ///
    /// This is *not* the finalized checkpoint of the `head_snapshot.beacon_state`, rather it is the
    /// best finalized checkpoint that has been observed by `self.fork_choice`. It is possible that
    /// the `head_snapshot.beacon_state` finalized value is earlier than the one returned here.
    pub fn finalized_checkpoint(&self) -> Checkpoint {
        self.fork_choice_view.finalized_checkpoint
    }

    /// Returns the finalized checkpoint, as determined by fork choice.
    ///
    /// ## Note
    ///
    /// This is *not* the "current justified checkpoint" of the `head_snapshot.beacon_state`, rather
    /// it is the justified checkpoint in the view of `self.fork_choice`. It is possible that the
    /// `head_snapshot.beacon_state` justified value is different to, but not conflicting with, the
    /// one returned here.
    pub fn justified_checkpoint(&self) -> Checkpoint {
        self.fork_choice_view.finalized_checkpoint
    }
}
