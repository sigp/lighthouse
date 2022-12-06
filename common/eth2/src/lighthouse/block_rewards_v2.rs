use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
// TODO: Discuss name BlockRewardsV2
pub struct BlockRewardsV2 {

    pub execution_optimistic: bool,

    pub finalized: bool,

    pub data: Vec<BlockRewardV2>,

}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]

pub struct BlockRewardV2 {

    pub proposer_index: u64,

    pub total: u64,

    pub attestations: u64,

    pub sync_aggregate: u64,

    pub proposer_slashings: u64,

    pub attester_slashings: u64,

}
