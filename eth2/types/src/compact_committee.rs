use crate::Pubkey;
use tree_hash_derive::{CachedTreeHash, TreeHash};

/// Spec v0.8.0
#[derive(Default, Clone, Debug, PartialEq, TreeHash, CachedTreeHash)]
pub struct CompactCommittee {
    pub pubkeys: Vec<Pubkey>,
    pub compact_validators: Vec<u64>,
}
