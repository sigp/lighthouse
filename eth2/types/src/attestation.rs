use super::{AggregateSignature, AttestationData, Bitfield};
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz::TreeHash;
use ssz_derive::{Decode, Encode, SignedRoot, TreeHash};
use test_random_derive::TestRandom;

/// Details an attestation that can be slashable.
///
/// Spec v0.5.0
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
pub struct Attestation {
    pub aggregation_bitfield: Bitfield,
    pub data: AttestationData,
    pub custody_bitfield: Bitfield,
    pub aggregate_signature: AggregateSignature,
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
        // FIXME: signature aggregation once our BLS library wraps it
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Attestation);
}
