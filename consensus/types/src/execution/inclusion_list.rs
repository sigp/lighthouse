use crate::{ForkName, Hash256, SignedRoot, Slot, Transactions};
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
    pub inclusion_list_committee_root: Hash256,
    // TODO(heze): switch to using `ProgressiveList` once the support for EIP-7916 is added.
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions: Transactions,
}

impl SignedRoot for InclusionList {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(InclusionList);
}
