use crate::database::{
    schema::{
        beacon_blocks, block_packing, block_rewards, canonical_slots, proposer_info,
        suboptimal_attestations, validators,
    },
    watch_types::{WatchAttestation, WatchHash, WatchPK, WatchSlot},
};
use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

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
}

#[derive(Clone, Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = validators)]
pub struct WatchValidator {
    pub index: i32,
    pub public_key: WatchPK,
    pub status: String,
    pub client: Option<String>,
    pub activation_epoch: Option<i32>,
    pub exit_epoch: Option<i32>,
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

#[derive(Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = proposer_info)]
pub struct WatchProposerInfo {
    pub slot: WatchSlot,
    pub proposer_index: i32,
    pub graffiti: String,
}

#[derive(Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = block_rewards)]
pub struct WatchBlockRewards {
    pub slot: WatchSlot,
    pub total: i32,
    pub attestation_reward: i32,
    pub sync_committee_reward: i32,
}

#[derive(Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = block_packing)]
pub struct WatchBlockPacking {
    pub slot: WatchSlot,
    pub available: i32,
    pub included: i32,
    pub prior_skip_slots: i32,
}

#[derive(Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = suboptimal_attestations)]
pub struct WatchSuboptimalAttestation {
    pub epoch_start_slot: WatchSlot,
    pub index: i32,
    pub source: bool,
    pub head: bool,
    pub target: bool,
}

impl WatchSuboptimalAttestation {
    pub fn to_attestation(&self, slots_per_epoch: u64) -> WatchAttestation {
        WatchAttestation {
            index: self.index,
            epoch: self.epoch_start_slot.epoch(slots_per_epoch),
            source: self.source,
            head: self.head,
            target: self.target,
        }
    }
}
