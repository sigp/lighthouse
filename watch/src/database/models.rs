use crate::database::{
    schema::{
        beacon_blocks, block_packing, block_rewards, canonical_slots, proposer_info, validators,
    },
    watch_types::{WatchHash, WatchPK, WatchSlot},
};
use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};

#[derive(Debug, Queryable, Insertable)]
#[diesel(table_name = canonical_slots)]
pub struct WatchCanonicalSlot {
    pub slot: WatchSlot,
    pub root: WatchHash,
    pub skipped: bool,
    pub beacon_block: Option<WatchHash>,
}

#[derive(Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = beacon_blocks)]
pub struct WatchBeaconBlock {
    pub root: WatchHash,
    pub parent_root: WatchHash,
    pub slot: WatchSlot,
}

#[derive(Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = proposer_info)]
pub struct WatchProposerInfo {
    pub block_root: WatchHash,
    pub slot: WatchSlot,
    pub proposer_index: i32,
    pub graffiti: String,
}

#[derive(Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = block_rewards)]
pub struct WatchBlockRewards {
    pub block_root: WatchHash,
    pub slot: WatchSlot,
    pub total: i32,
    pub attestation_reward: i32,
    pub sync_committee_reward: i32,
}

#[derive(Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = block_packing)]
pub struct WatchBlockPacking {
    pub block_root: WatchHash,
    pub slot: WatchSlot,
    pub available: i32,
    pub included: i32,
    pub prior_skip_slots: i32,
}

#[derive(Debug, Queryable, Insertable)]
#[diesel(table_name = validators)]
pub struct WatchValidator {
    pub id: i32,
    pub validator_index: i32,
    pub public_key: WatchPK,
}
