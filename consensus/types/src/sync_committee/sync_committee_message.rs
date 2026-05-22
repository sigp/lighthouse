use bls::{SecretKey, Signature};
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{
    core::{ChainSpec, Domain, EthSpec, Hash256, SignedRoot, Slot, SlotData},
    fork::{Fork, ForkName},
};

/// The data upon which a `SyncCommitteeContribution` is based.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct SyncCommitteeMessage {
    pub slot: Slot,
    pub beacon_block_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    // Signature by the validator over `beacon_block_root`.
    pub signature: Signature,
}

impl SyncCommitteeMessage {
    /// Equivalent to `get_sync_committee_message` from the spec.
    pub fn new<E: EthSpec>(
        slot: Slot,
        beacon_block_root: Hash256,
        validator_index: u64,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Self {
        let epoch = slot.epoch(E::slots_per_epoch());
        let domain = spec.get_domain(epoch, Domain::SyncCommittee, fork, genesis_validators_root);
        let message = beacon_block_root.signing_root(domain);
        let signature = secret_key.sign(message);
        Self {
            slot,
            beacon_block_root,
            validator_index,
            signature,
        }
    }
}

impl SlotData for SyncCommitteeMessage {
    fn get_slot(&self) -> Slot {
        self.slot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SyncCommitteeMessage);
}
