use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use types::{Hash256, Slot};

/// Details about the rewards paid to a block proposer for proposing a block.
///
/// All rewards in GWei.
///
/// Presently this only counts attestation rewards, but in future should be expanded
/// to include information on slashings and sync committee aggregates too.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BlockReward {
    /// Block root of the block that these rewards are for.
    pub block_root: Hash256,
    /// Rewards due to attestations.
    pub attestation_rewards: AttestationRewards,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AttestationRewards {
    /// Total block reward from attestations included.
    pub total: u64,
    /// Total rewards from previous epoch attestations.
    pub prev_epoch_total: u64,
    /// Total rewards from current epoch attestations.
    pub curr_epoch_total: u64,
    /// Map from validator index to reward for including that validator's prev epoch attestation.
    pub prev_epoch_rewards: HashMap<u64, u64>,
    /// Map from validator index to reward for including that validator's current epoch attestation.
    pub curr_epoch_rewards: HashMap<u64, u64>,
    /// Vec of attestation rewards for each attestation included.
    ///
    /// Each element of the vec is a map from validator index to reward.
    pub per_attestation_rewards: Vec<HashMap<u64, u64>>,
}

/// Query parameters for the `/lighthouse/block_rewards` endpoint.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BlockRewardsQuery {
    /// Lower slot limit for block rewards returned (inclusive).
    pub start_slot: Slot,
    /// Upper slot limit for block rewards returned (inclusive).
    pub end_slot: Slot,
}
