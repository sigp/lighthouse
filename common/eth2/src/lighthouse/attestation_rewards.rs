use serde::{Deserialize, Serialize};

// Details about the rewards paid for attestations
// All rewards in GWei

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
// TODO: AttestationRewards already exists
pub struct AttestationRewardsTBD {

    pub execution_optimistic: bool,

    pub finalized: bool,

    pub data: Vec<AttestationRewardTBD>,

}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AttestationRewardTBD {
    // Ideal rewards info for a single attestation
    pub ideal_rewards: Vec<IdealAttestationRewards>,
    // Rewards info for a single attestation
    pub total_rewards: Vec<TotalAttestationRewards>,

}

// TODO Types for negative values need to be added
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
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

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct TotalAttestationRewards {
    // one entry for every validator based on their attestations in the epoch
    pub validaor_index: u64,
    // attester's reward for head vote in gwei
    pub head: i64,
    // attester's reward for target vote in gwei
    pub target: i64,
    // attester's reward for source vote in gwei
    pub source: i64,
    // attester's inclusion_delay reward in gwei (phase0 only)
    pub inclusion_delay: u64,

}