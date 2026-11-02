use crate::ForkName;
use crate::execution::InclusionList;
use bls::Signature;
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz::{BYTES_PER_LENGTH_OFFSET, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[derive(TreeHash, Debug, Clone, Encode, Decode, Serialize, Deserialize, Educe)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[educe(PartialEq, Hash)]
#[context_deserialize(ForkName)]
pub struct SignedInclusionList {
    pub message: InclusionList,
    pub signature: Signature,
}

impl SignedInclusionList {
    /// Returns the minimum SSZ-encoded size (no transactions).
    pub fn min_size() -> usize {
        Self {
            message: InclusionList::default(),
            signature: Signature::empty(),
        }
        .as_ssz_bytes()
        .len()
    }

    /// Returns the maximum SSZ-encoded size. The worst case is `max_transactions_bytes`
    /// single-byte transactions, since each one also costs a 4 byte offset.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn max_size(max_transactions_bytes: usize) -> usize {
        Self::min_size() + max_transactions_bytes * (BYTES_PER_LENGTH_OFFSET + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChainSpec;

    ssz_and_tree_hash_tests!(SignedInclusionList);

    #[test]
    fn max_size_matches_the_preset() {
        let spec = ChainSpec::mainnet();
        // `MAX_SIGNED_INCLUSION_LIST_SIZE` from the Heze preset.
        assert_eq!(
            SignedInclusionList::max_size(spec.max_transactions_bytes_per_inclusion_list as usize),
            41112
        );
    }
}
