use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use types::{AttestationData, Hash256, Slot};

/// Details about the rewards paid to a block proposer for proposing a block.
///
/// All rewards in GWei.
///
/// Presently this only counts attestation rewards, but in future should be expanded
/// to include information on slashings and sync committee aggregates too.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BlockReward {
    /// Sum of all reward components.
    pub total: u64,
    /// Block root of the block that these rewards are for.
    pub block_root: Hash256,
    /// Metadata about the block, particularly reward-relevant metadata.
    pub meta: BlockRewardMeta,
    /// Rewards due to attestations.
    pub attestation_rewards: AttestationRewards,
    /// Sum of rewards due to sync committee signatures.
    pub sync_committee_rewards: u64,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BlockRewardMeta {
    pub slot: Slot,
    pub parent_slot: Slot,
    pub proposer_index: u64,
    pub graffiti: String,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AttestationRewards {
    /// Total block reward from attestations included.
    pub total: u64,
    /// Total rewards from previous epoch attestations.
    pub prev_epoch_total: u64,
    /// Total rewards from current epoch attestations.
    pub curr_epoch_total: u64,
    /// Vec of attestation rewards for each attestation included.
    ///
    /// Each element of the vec is a map from validator index to reward.
    pub per_attestation_rewards: Vec<HashMap<u64, u64>>,
    /// The attestations themselves (optional).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<AttestationData>,
}

/// Query parameters for the `/lighthouse/block_rewards` endpoint.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BlockRewardsQuery {
    /// Lower slot limit for block rewards returned (inclusive).
    pub start_slot: Slot,
    /// Upper slot limit for block rewards returned (inclusive).
    pub end_slot: Slot,
    /// Include the full attestations themselves?
    #[serde(default)]
    pub include_attestations: bool,
}
