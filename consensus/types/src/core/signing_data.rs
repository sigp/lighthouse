use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{core::Hash256, fork::ForkName, test_utils::TestRandom};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
#[context_deserialize(ForkName)]
pub struct SigningData {
    pub object_root: Hash256,
    pub domain: Hash256,
}

pub trait SignedRoot: TreeHash {
    fn signing_root(&self, domain: Hash256) -> Hash256 {
        SigningData {
            object_root: self.tree_hash_root(),
            domain,
        }
        .tree_hash_root()
    }
}
