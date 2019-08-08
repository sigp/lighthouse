use crate::{test_utils::TestRandom, AggregateSignature, AttestationData, EthSpec, VariableList};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::{SignedRoot, TreeHash};

/// Details an attestation that can be slashable.
///
/// To be included in an `AttesterSlashing`.
///
/// Spec v0.8.0
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    SignedRoot,
)]
#[serde(bound = "T: EthSpec")]
pub struct IndexedAttestation<T: EthSpec> {
    /// Lists validator registry indices, not committee indices.
    pub custody_bit_0_indices: VariableList<u64, T::MaxValidatorsPerCommittee>,
    pub custody_bit_1_indices: VariableList<u64, T::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
    #[signed_root(skip_hashing)]
    pub signature: AggregateSignature,
}

impl<T: EthSpec> IndexedAttestation<T> {
    /// Check if ``attestation_data_1`` and ``attestation_data_2`` have the same target.
    ///
    /// Spec v0.8.0
    pub fn is_double_vote(&self, other: &Self) -> bool {
        self.data.target.epoch == other.data.target.epoch && self.data != other.data
    }

    /// Check if ``attestation_data_1`` surrounds ``attestation_data_2``.
    ///
    /// Spec v0.8.0
    pub fn is_surround_vote(&self, other: &Self) -> bool {
        self.data.source.epoch < other.data.source.epoch
            && other.data.target.epoch < self.data.target.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot_epoch::Epoch;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use crate::MainnetEthSpec;

    #[test]
    pub fn test_is_double_vote_true() {
        let indexed_vote_first = create_indexed_attestation(3, 1);
        let indexed_vote_second = create_indexed_attestation(3, 2);

        assert_eq!(
            indexed_vote_first.is_double_vote(&indexed_vote_second),
            true
        )
    }

    #[test]
    pub fn test_is_double_vote_false() {
        let indexed_vote_first = create_indexed_attestation(1, 1);
        let indexed_vote_second = create_indexed_attestation(2, 1);

        assert_eq!(
            indexed_vote_first.is_double_vote(&indexed_vote_second),
            false
        );
    }

    #[test]
    pub fn test_is_surround_vote_true() {
        let indexed_vote_first = create_indexed_attestation(2, 1);
        let indexed_vote_second = create_indexed_attestation(1, 2);

        assert_eq!(
            indexed_vote_first.is_surround_vote(&indexed_vote_second),
            true
        );
    }

    #[test]
    pub fn test_is_surround_vote_true_realistic() {
        let indexed_vote_first = create_indexed_attestation(4, 1);
        let indexed_vote_second = create_indexed_attestation(3, 2);

        assert_eq!(
            indexed_vote_first.is_surround_vote(&indexed_vote_second),
            true
        );
    }

    #[test]
    pub fn test_is_surround_vote_false_source_epoch_fails() {
        let indexed_vote_first = create_indexed_attestation(2, 2);
        let indexed_vote_second = create_indexed_attestation(1, 1);

        assert_eq!(
            indexed_vote_first.is_surround_vote(&indexed_vote_second),
            false
        );
    }

    #[test]
    pub fn test_is_surround_vote_false_target_epoch_fails() {
        let indexed_vote_first = create_indexed_attestation(1, 1);
        let indexed_vote_second = create_indexed_attestation(2, 2);

        assert_eq!(
            indexed_vote_first.is_surround_vote(&indexed_vote_second),
            false
        );
    }

    ssz_tests!(IndexedAttestation<MainnetEthSpec>);

    fn create_indexed_attestation(
        target_epoch: u64,
        source_epoch: u64,
    ) -> IndexedAttestation<MainnetEthSpec> {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut indexed_vote = IndexedAttestation::random_for_test(&mut rng);

        indexed_vote.data.source.epoch = Epoch::new(source_epoch);
        indexed_vote.data.target.epoch = Epoch::new(target_epoch);
        indexed_vote
    }
}
