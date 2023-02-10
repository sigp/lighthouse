use serde::{Deserialize, Serialize};

// Details about the rewards paid for attestations
// All rewards in GWei

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct IdealAttestationRewards {
    // Validator's effective balance in gwei
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub effective_balance: u64,
    // Ideal attester's reward for head vote in gwei
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub head: u64,
    // Ideal attester's reward for target vote in gwei
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub target: u64,
    // Ideal attester's reward for source vote in gwei
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub source: u64,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TotalAttestationRewards {
    // one entry for every validator based on their attestations in the epoch
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub validator_index: u64,
    // attester's reward for head vote in gwei
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub head: u64,
    // attester's reward for target vote in gwei
    pub target: i64,
    // attester's reward for source vote in gwei
    pub source: i64,
    // TBD attester's inclusion_delay reward in gwei (phase0 only)
    // pub inclusion_delay: u64,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct StandardAttestationRewards {
    pub ideal_rewards: Vec<IdealAttestationRewards>,
    pub total_rewards: Vec<TotalAttestationRewards>,
}
