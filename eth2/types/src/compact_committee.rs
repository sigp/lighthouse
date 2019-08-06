use crate::test_utils::TestRandom;
use crate::{EthSpec, PublicKey};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Spec v0.8.0
#[derive(Clone, Debug, PartialEq, TreeHash, Encode, Decode, Serialize, Deserialize, TestRandom)]
#[serde(bound = "T: EthSpec")]
pub struct CompactCommittee<T: EthSpec> {
    pub pubkeys: VariableList<PublicKey, T::MaxValidatorsPerCommittee>,
    pub compact_validators: VariableList<u64, T::MaxValidatorsPerCommittee>,
}

impl<T: EthSpec> Default for CompactCommittee<T> {
    fn default() -> Self {
        Self {
            pubkeys: VariableList::empty(),
            compact_validators: VariableList::empty(),
        }
    }
}
