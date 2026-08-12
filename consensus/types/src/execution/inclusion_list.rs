use crate::{ForkName, Hash256, ProgressiveTransactions, SignedRoot, Slot};
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[derive(Default, Debug, Clone, Serialize, Encode, Decode, Deserialize, TreeHash, Educe)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[educe(PartialEq, Hash)]
#[context_deserialize(ForkName)]
pub struct InclusionList {
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub dependent_root: Hash256,
    #[serde(with = "ssz_types::serde_utils::prog_list_of_hex_prog_var_list")]
    pub transactions: ProgressiveTransactions,
}

impl SignedRoot for InclusionList {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(InclusionList);
}
