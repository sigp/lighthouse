use serde::{Deserialize, Serialize};

// Details about the rewards for a single block
// All rewards in GWei
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct StandardBlockReward {
    // proposer of the block, the proposer index who receives these rewards
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    // total block reward in gwei,
    // equal to attestations + sync_aggregate + proposer_slashings + attester_slashings
    #[serde(with = "serde_utils::quoted_u64")]
    pub total: u64,
    // block reward component due to included attestations in gwei
    #[serde(with = "serde_utils::quoted_u64")]
    pub attestations: u64,
    // block reward component due to included sync_aggregate in gwei
    #[serde(with = "serde_utils::quoted_u64")]
    pub sync_aggregate: u64,
    // block reward component due to included proposer_slashings in gwei
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_slashings: u64,
    // block reward component due to included attester_slashings in gwei
    #[serde(with = "serde_utils::quoted_u64")]
    pub attester_slashings: u64,
}
