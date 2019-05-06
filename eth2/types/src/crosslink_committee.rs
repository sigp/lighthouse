use crate::*;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::{CachedTreeHash, TreeHash};

#[derive(
    Default,
    Clone,
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    Decode,
    Encode,
    TreeHash,
    CachedTreeHash,
)]
pub struct CrosslinkCommittee {
    pub slot: Slot,
    pub shard: Shard,
    pub committee: Vec<usize>,
}
