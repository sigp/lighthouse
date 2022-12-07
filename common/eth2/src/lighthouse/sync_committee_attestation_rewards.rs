use serde::{Deserialize, Serialize};

// Details about the rewards paid to sync committee members for attesting headers
// All rewards in GWei

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct SyncCommitteeAttestationRewards {

    pub execution_optimistic: bool,

    pub finalized: bool,

    pub data: Vec<SyncCommitteeAttestationReward>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct SyncCommitteeAttestationReward {

    pub validator_index: u8,
    // sync committee reward in gwei for the validator
    pub reward: u64,

}
