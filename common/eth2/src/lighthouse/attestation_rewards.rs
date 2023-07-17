use serde::{Deserialize, Serialize};
use serde_utils::quoted_u64::Quoted;

// Details about the rewards paid for attestations
// All rewards in GWei

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct IdealAttestationRewards {
    // Validator's effective balance in gwei
    #[serde(with = "serde_utils::quoted_u64")]
    pub effective_balance: u64,
    // Ideal attester's reward for head vote in gwei
    #[serde(with = "serde_utils::quoted_u64")]
    pub head: u64,
    // Ideal attester's reward for target vote in gwei
    #[serde(with = "serde_utils::quoted_u64")]
    pub target: u64,
    // Ideal attester's reward for source vote in gwei
    #[serde(with = "serde_utils::quoted_u64")]
    pub source: u64,
    // Ideal attester's inclusion_delay reward in gwei (phase0 only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusion_delay: Option<Quoted<u64>>,
    // Ideal attester's inactivity penalty in gwei
    #[serde(with = "serde_utils::quoted_i64")]
    pub inactivity: i64,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TotalAttestationRewards {
    // one entry for every validator based on their attestations in the epoch
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    // attester's reward for head vote in gwei
    #[serde(with = "serde_utils::quoted_i64")]
    pub head: i64,
    // attester's reward for target vote in gwei
    #[serde(with = "serde_utils::quoted_i64")]
    pub target: i64,
    // attester's reward for source vote in gwei
    #[serde(with = "serde_utils::quoted_i64")]
    pub source: i64,
    // attester's inclusion_delay reward in gwei (phase0 only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusion_delay: Option<Quoted<u64>>,
    // attester's inactivity penalty in gwei
    #[serde(with = "serde_utils::quoted_i64")]
    pub inactivity: i64,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct StandardAttestationRewards {
    pub ideal_rewards: Vec<IdealAttestationRewards>,
    pub total_rewards: Vec<TotalAttestationRewards>,
}
