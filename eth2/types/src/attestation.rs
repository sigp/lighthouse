use super::{AggregateSignature, AttestationData, Bitfield};
use crate::test_utils::TestRandom;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::{CachedTreeHash, SignedRoot, TreeHash};

/// Details an attestation that can be slashable.
///
/// Spec v0.6.1
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    CachedTreeHash,
    TestRandom,
    SignedRoot,
)]
pub struct Attestation {
    pub aggregation_bitfield: Bitfield,
    pub data: AttestationData,
    pub custody_bitfield: Bitfield,
    #[signed_root(skip_hashing)]
    pub signature: AggregateSignature,
}

impl Attestation {
    /// Are the aggregation bitfields of these attestations disjoint?
    pub fn signers_disjoint_from(&self, other: &Attestation) -> bool {
        self.aggregation_bitfield
            .intersection(&other.aggregation_bitfield)
            .is_zero()
    }

    /// Aggregate another Attestation into this one.
    ///
    /// The aggregation bitfields must be disjoint, and the data must be the same.
    pub fn aggregate(&mut self, other: &Attestation) {
        debug_assert_eq!(self.data, other.data);
        debug_assert!(self.signers_disjoint_from(other));

        self.aggregation_bitfield
            .union_inplace(&other.aggregation_bitfield);
        self.custody_bitfield.union_inplace(&other.custody_bitfield);
        self.signature.add_aggregate(&other.signature);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Attestation);
    cached_tree_hash_tests!(Attestation);
}
