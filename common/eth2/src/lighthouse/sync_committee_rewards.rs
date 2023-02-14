use serde::{Deserialize, Serialize};

// Details about the rewards paid to sync committee members for attesting headers
// All rewards in GWei

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct SyncCommitteeReward {
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub validator_index: u64,
    // sync committee reward in gwei for the validator
    #[serde(with = "eth2_serde_utils::quoted_i64")]
    pub reward: i64,
}
