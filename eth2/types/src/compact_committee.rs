use crate::{EthSpec, Pubkey};
use ssz_types::VariableList;
use tree_hash_derive::{CachedTreeHash, TreeHash};

/// Spec v0.8.0
#[derive(Default, Clone, Debug, PartialEq, TreeHash, CachedTreeHash)]
pub struct CompactCommittee<T: EthSpec> {
    pub pubkeys: VariableList<Pubkey, T::MaxValidatorsPerCommittee>,
    pub compact_validators: VariableList<u64, T::MaxValidatorsPerCommittee>,
}
