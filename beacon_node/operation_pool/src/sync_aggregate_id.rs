use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use types::{Hash256, Slot};

/// Used to key `SyncAggregate`s in the `naive_sync_aggregation_pool`.
#[derive(
    PartialEq, Eq, Clone, Hash, Debug, PartialOrd, Ord, Encode, Decode, Serialize, Deserialize,
)]
pub struct SyncAggregateId {
    pub slot: Slot,
    pub beacon_block_root: Hash256,
}

impl SyncAggregateId {
    pub fn new(slot: Slot, beacon_block_root: Hash256) -> Self {
        Self {
            slot,
            beacon_block_root,
        }
    }
}
