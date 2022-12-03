use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use types::{AttestationData, Hash256, Slot};

/// Details about the rewards paid to sync committee members for attesting headers
///
/// All rewards in GWei.
///
/// Presently this only counts attestation rewards, but in future should be expanded
/// to include information on slashings and sync committee aggregates too.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct SyncCommitteeAttestationRewards {

    pub execution_optimistic: bool,

    pub finalized: bool,

    pub data: Vec<SyncCommitteeAttestationReward>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct SyncCommitteeAttestationReward {

    pub validator_index: u8,

    pub reward: u64,

}
