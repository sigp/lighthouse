use crate::database::{
    schema::{
        beacon_blocks, block_packing, block_rewards, canonical_slots, proposer_info,
        suboptimal_attestations, validators,
    },
    watch_types::{WatchAttestation, WatchHash, WatchPK, WatchSlot},
};
use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = validators)]
pub struct WatchValidator {
    pub index: i32,
    pub public_key: WatchPK,
    pub status: String,
    pub balance: i64,
    pub activation_epoch: i32,
    pub exit_epoch: Option<i32>,
}

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
