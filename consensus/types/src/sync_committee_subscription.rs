use crate::Epoch;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

/// A sync committee subscription created when a validator subscribes to sync committee subnets to perform
/// sync committee duties.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Encode, Decode)]
pub struct SyncCommitteeSubscription {
    /// The validators index.
    pub validator_index: u64,
    /// The sync committee indices.
    pub sync_committee_indices: Vec<u64>,
    /// Epoch until which this subscription is required.
    pub until_epoch: Epoch,
}
