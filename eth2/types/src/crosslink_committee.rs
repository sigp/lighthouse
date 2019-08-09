use crate::*;
use tree_hash_derive::TreeHash;

#[derive(Default, Clone, Debug, PartialEq, TreeHash)]
pub struct CrosslinkCommittee<'a> {
    pub slot: Slot,
    pub shard: Shard,
    pub committee: &'a [usize],
}

impl<'a> CrosslinkCommittee<'a> {
    pub fn into_owned(self) -> OwnedCrosslinkCommittee {
        OwnedCrosslinkCommittee {
            slot: self.slot,
            shard: self.shard,
            committee: self.committee.to_vec(),
        }
    }
}

#[derive(Default, Clone, Debug, PartialEq, TreeHash)]
pub struct OwnedCrosslinkCommittee {
    pub slot: Slot,
    pub shard: Shard,
    pub committee: Vec<usize>,
}
