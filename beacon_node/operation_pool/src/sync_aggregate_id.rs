use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use types::{ChainSpec, Domain, EthSpec, Fork, Hash256, Slot};

/// Used to key `SyncAggregate`s in the `naive_sync_aggregation_pool`.
#[derive(
    PartialEq, Eq, Clone, Hash, Debug, PartialOrd, Ord, Encode, Decode, Serialize, Deserialize,
)]
pub struct SyncAggregateId {
    pub slot: Slot,
    pub beacon_block_root: Hash256,
    pub domain: Hash256,
}

impl SyncAggregateId {
    pub fn from_data<T: EthSpec>(
        slot: Slot,
        beacon_block_root: Hash256,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Self {
        let epoch = slot.epoch(T::slots_per_epoch());
        let domain = spec.get_domain(epoch, Domain::SyncCommittee, fork, genesis_validators_root);

        Self {
            slot,
            beacon_block_root,
            domain,
        }
    }
}
