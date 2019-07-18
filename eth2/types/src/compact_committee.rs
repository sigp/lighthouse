use crate::{EthSpec, PublicKey};
use ssz_types::VariableList;
use tree_hash_derive::{CachedTreeHash, TreeHash};

/// Spec v0.8.0
#[derive(Clone, Debug, PartialEq, TreeHash, CachedTreeHash)]
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
