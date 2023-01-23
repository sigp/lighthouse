use serde::{Deserialize, Serialize};

// Details about the rewards paid for attestations
// All rewards in GWei

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct IdealAttestationRewards {
    // Validator's effective balance in gwei
    pub effective_balance: u64,
    // Ideal attester's reward for head vote in gwei
    pub head: u64,
    // Ideal attester's reward for target vote in gwei
    pub target: u64,
    // Ideal attester's reward for source vote in gwei
    pub source: u64,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TotalAttestationRewards {
    // one entry for every validator based on their attestations in the epoch
    pub validator_index: u64,
    // attester's reward for head vote in gwei
    pub head: i64,
    // attester's reward for target vote in gwei
    pub target: i64,
    // attester's reward for source vote in gwei
    pub source: i64,
    // attester's inclusion_delay reward in gwei (phase0 only)
    pub inclusion_delay: u64,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
//TODO: AttestationRewards already exists
pub struct AttestationRewardsV2 {
    pub ideal_rewards: Vec<IdealAttestationRewards>,
    pub total_rewards: Vec<TotalAttestationRewards>,
}
