use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
// TODO: AttestationRewards already exists
pub struct AttestationRewardsTBD {

    pub execution_optimistic: bool,

    pub finalized: bool,

    pub data: Vec<AttestationRewardTBD>,

}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AttestationRewardTBD {

    pub ideal_rewards: Vec<IdealAttestationRewards>,

    pub total_rewards: Vec<TotalAttestationRewards>,

}

// TODO Types for negative values need to be added
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct IdealAttestationRewards {

    pub effective_balance: String,

    pub head: u64,

    pub target: u64,

    pub source: u64,

}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct TotalAttestationRewards {

    pub validaor_index: u64,

    pub head: u64,

    pub target: u64,

    pub source: u64,

    pub inclusion_delay: u64,

}