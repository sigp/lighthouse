use super::{AggregateSignature, AttestationData, BitList, EthSpec};
use crate::test_utils::TestRandom;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::{SignedRoot, TreeHash};

/// Details an attestation that can be slashable.
///
/// Spec v0.8.0
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    SignedRoot,
)]
#[serde(bound = "T: EthSpec")]
pub struct Attestation<T: EthSpec> {
    pub aggregation_bits: BitList<T::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
    pub custody_bits: BitList<T::MaxValidatorsPerCommittee>,
    #[signed_root(skip_hashing)]
    pub signature: AggregateSignature,
}

impl<T: EthSpec> Attestation<T> {
    /// Are the aggregation bitfields of these attestations disjoint?
    pub fn signers_disjoint_from(&self, other: &Self) -> bool {
        self.aggregation_bits
            .intersection(&other.aggregation_bits)
            .is_zero()
    }

    /// Aggregate another Attestation into this one.
    ///
    /// The aggregation bitfields must be disjoint, and the data must be the same.
    pub fn aggregate(&mut self, other: &Self) {
        debug_assert_eq!(self.data, other.data);
        debug_assert!(self.signers_disjoint_from(other));

        self.aggregation_bits = self.aggregation_bits.union(&other.aggregation_bits);
        self.custody_bits = self.custody_bits.union(&other.custody_bits);
        self.signature.add_aggregate(&other.signature);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    ssz_tests!(Attestation<MainnetEthSpec>);
}
