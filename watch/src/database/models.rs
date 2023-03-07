use crate::database::{
    schema::{beacon_blocks, canonical_slots, proposer_info, validators},
    watch_types::{WatchHash, WatchPK, WatchSlot},
};
use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

pub type WatchEpoch = i32;

#[derive(Debug, Queryable, Insertable, Serialize, Deserialize)]
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
    pub slot: WatchSlot,
    pub root: WatchHash,
    pub parent_root: WatchHash,
    pub attestation_count: i32,
    pub transaction_count: Option<i32>,
    pub withdrawal_count: Option<i32>,
}

#[derive(Clone, Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = validators)]
pub struct WatchValidator {
    pub index: i32,
    pub public_key: WatchPK,
    pub status: String,
    pub activation_epoch: Option<WatchEpoch>,
    pub exit_epoch: Option<WatchEpoch>,
}

// Implement a minimal version of `Hash` and `Eq` so that we know if a validator status has changed.
impl Hash for WatchValidator {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.index.hash(state);
        self.status.hash(state);
        self.activation_epoch.hash(state);
        self.exit_epoch.hash(state);
    }
}

impl PartialEq for WatchValidator {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
            && self.status == other.status
            && self.activation_epoch == other.activation_epoch
            && self.exit_epoch == other.exit_epoch
    }
}
impl Eq for WatchValidator {}

#[derive(Clone, Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = proposer_info)]
pub struct WatchProposerInfo {
    pub slot: WatchSlot,
    pub proposer_index: i32,
    pub graffiti: String,
}
