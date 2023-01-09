use serde::{Deserialize, Serialize};

// Details about the rewards paid to sync committee members for attesting headers
// All rewards in GWei

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct SyncCommitteeRewards {

    pub execution_optimistic: Option<bool>,

    pub finalized: Option<bool>,

    pub data: Option<Vec<SyncCommitteeReward>> 
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct SyncCommitteeReward {

    pub validator_index: u64,
    // sync committee reward in gwei for the validator
    pub reward: i64,

}
