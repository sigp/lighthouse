use crate::*;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::hash::Hash;

#[derive(Debug, PartialEq, Clone, Hash, Serialize, Deserialize, Encode, Decode)]
pub struct ShufflingId {
    shuffling_epoch: Epoch,
    shuffling_decision_block: Hash256,
}

impl ShufflingId {
    pub fn new<E: EthSpec>(
        block_root: Hash256,
        state: &BeaconState<E>,
        relative_epoch: RelativeEpoch,
    ) -> Result<Self, BeaconStateError> {
        let shuffling_epoch = relative_epoch.into_epoch(state.current_epoch());

        // Taking advantage of saturating subtraction on slot and epoch.
        //
        // This is the final slot of the penultimate epoch.
        let shuffling_decision_slot =
            (state.current_epoch() - 1).start_slot(E::slots_per_epoch()) - 1;

        let shuffling_decision_block = if state.slot == shuffling_decision_slot {
            block_root
        } else {
            *state.get_block_root(shuffling_decision_slot)?
        };

        Ok(Self {
            shuffling_epoch,
            shuffling_decision_block,
        })
    }

    pub fn from_components(shuffling_epoch: Epoch, shuffling_decision_block: Hash256) -> Self {
        Self {
            shuffling_epoch,
            shuffling_decision_block,
        }
    }

    pub fn set_epoch(&mut self, epoch: Epoch) {
        self.shuffling_epoch = epoch;
    }
}

impl Eq for ShufflingId {}
