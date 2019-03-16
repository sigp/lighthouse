use crate::*;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode, TreeHash};

#[derive(Default, Clone, Debug, PartialEq, Serialize, Deserialize, Decode, Encode, TreeHash)]
pub struct CrosslinkCommittee {
    pub shard: Shard,
    pub committee: Vec<usize>,
}
