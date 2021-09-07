use crate::test_utils::TestRandom;
use crate::{ChainSpec, Domain, EthSpec, Fork, Hash256, SecretKey, Signature, SignedRoot, Slot};

use crate::slot_data::SlotData;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// The data upon which a `SyncCommitteeContribution` is based.
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct SyncCommitteeMessage {
    pub slot: Slot,
    pub beacon_block_root: Hash256,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
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
