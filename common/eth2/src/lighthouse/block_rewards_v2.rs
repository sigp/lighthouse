use serde::{Deserialize, Serialize};

// Details about the rewards for a single block
// All rewards in GWei

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
// TODO: Discuss name BlockRewardsV2
pub struct BlockRewardsV2 {

    pub execution_optimistic: bool,

    pub finalized: bool,

    pub data: Vec<BlockRewardV2>,

}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]

pub struct BlockRewardV2 {
    // proposer of the block, the proposer index who receives these rewards
    pub proposer_index: u64,
    // total block reward in gwei,
    // equal to attestations + sync_aggregate + proposer_slashings + attester_slashings
    pub total: u64,
    // block reward component due to included attestations in gwei
    pub attestations: u64,
    // block reward component due to included sync_aggregate in gwei
    pub sync_aggregate: u64,
    // block reward component due to included proposer_slashings in gwei
    pub proposer_slashings: u64,
    // block reward component due to included attester_slashings in gwei
    pub attester_slashings: u64,

}
