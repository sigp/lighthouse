use crate::*;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::hash::Hash;

/// Can be used to key (ID) the shuffling in some chain, in some epoch.
///
/// ## Reasoning
///
/// We say that the ID of some shuffling is always equal to a 2-tuple:
///
/// - The epoch for which the shuffling should be effective.
/// - A block root, where this is the root at the *last* slot of the penultimate epoch. I.e., the
/// final block which contributed a randao reveal to the seed for the shuffling.
///
/// The struct stores exactly that 2-tuple.
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize, Encode, Decode)]
pub struct AttestationShufflingId {
    pub shuffling_epoch: Epoch,
    pub shuffling_decision_block: Hash256,
}

impl AttestationShufflingId {
    /// Using the given `state`, return the shuffling id for the shuffling at the given
    /// `relative_epoch`.
    ///
    /// The `block_root` provided should be either:
    ///
    /// - The root of the block which produced this state.
    /// - If the state is from a skip slot, the root of the latest block in that state.
    pub fn new<E: EthSpec>(
        block_root: Hash256,
        state: &BeaconState<E>,
        relative_epoch: RelativeEpoch,
    ) -> Result<Self, BeaconStateError> {
        let shuffling_epoch = relative_epoch.into_epoch(state.current_epoch());

        let shuffling_decision_block =
            state.attester_shuffling_decision_root(block_root, relative_epoch)?;

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
}
