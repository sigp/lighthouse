use crate::{test_utils::TestRandom, AggregateSignature, AttestationData, Bitfield, ChainSpec};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::{CachedTreeHash, SignedRoot, TreeHash};

/// Details an attestation that can be slashable.
///
/// To be included in an `AttesterSlashing`.
///
/// Spec v0.5.1
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    CachedTreeHash,
    TestRandom,
    SignedRoot,
)]
pub struct SlashableAttestation {
    /// Lists validator registry indices, not committee indices.
    pub validator_indices: Vec<u64>,
    pub data: AttestationData,
    pub custody_bitfield: Bitfield,
    #[signed_root(skip_hashing)]
    pub aggregate_signature: AggregateSignature,
}

impl SlashableAttestation {
    /// Check if ``attestation_data_1`` and ``attestation_data_2`` have the same target.
    ///
    /// Spec v0.5.1
    pub fn is_double_vote(&self, other: &SlashableAttestation, spec: &ChainSpec) -> bool {
        self.data.slot.epoch(spec.slots_per_epoch) == other.data.slot.epoch(spec.slots_per_epoch)
    }

    /// Check if ``attestation_data_1`` surrounds ``attestation_data_2``.
    ///
    /// Spec v0.5.1
    pub fn is_surround_vote(&self, other: &SlashableAttestation, spec: &ChainSpec) -> bool {
        let source_epoch_1 = self.data.source_epoch;
        let source_epoch_2 = other.data.source_epoch;
        let target_epoch_1 = self.data.slot.epoch(spec.slots_per_epoch);
        let target_epoch_2 = other.data.slot.epoch(spec.slots_per_epoch);

        (source_epoch_1 < source_epoch_2) & (target_epoch_2 < target_epoch_1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_spec::ChainSpec;
    use crate::slot_epoch::{Epoch, Slot};
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    #[test]
    pub fn test_is_double_vote_true() {
        let spec = ChainSpec::foundation();
        let slashable_vote_first = create_slashable_attestation(1, 1, &spec);
        let slashable_vote_second = create_slashable_attestation(1, 1, &spec);

        assert_eq!(
            slashable_vote_first.is_double_vote(&slashable_vote_second, &spec),
            true
        )
    }

    #[test]
    pub fn test_is_double_vote_false() {
        let spec = ChainSpec::foundation();
        let slashable_vote_first = create_slashable_attestation(1, 1, &spec);
        let slashable_vote_second = create_slashable_attestation(2, 1, &spec);

        assert_eq!(
            slashable_vote_first.is_double_vote(&slashable_vote_second, &spec),
            false
        );
    }

    #[test]
    pub fn test_is_surround_vote_true() {
        let spec = ChainSpec::foundation();
        let slashable_vote_first = create_slashable_attestation(2, 1, &spec);
        let slashable_vote_second = create_slashable_attestation(1, 2, &spec);

        assert_eq!(
            slashable_vote_first.is_surround_vote(&slashable_vote_second, &spec),
            true
        );
    }

    #[test]
    pub fn test_is_surround_vote_true_realistic() {
        let spec = ChainSpec::foundation();
        let slashable_vote_first = create_slashable_attestation(4, 1, &spec);
        let slashable_vote_second = create_slashable_attestation(3, 2, &spec);

        assert_eq!(
            slashable_vote_first.is_surround_vote(&slashable_vote_second, &spec),
            true
        );
    }

    #[test]
    pub fn test_is_surround_vote_false_source_epoch_fails() {
        let spec = ChainSpec::foundation();
        let slashable_vote_first = create_slashable_attestation(2, 2, &spec);
        let slashable_vote_second = create_slashable_attestation(1, 1, &spec);

        assert_eq!(
            slashable_vote_first.is_surround_vote(&slashable_vote_second, &spec),
            false
        );
    }

    #[test]
    pub fn test_is_surround_vote_false_target_epoch_fails() {
        let spec = ChainSpec::foundation();
        let slashable_vote_first = create_slashable_attestation(1, 1, &spec);
        let slashable_vote_second = create_slashable_attestation(2, 2, &spec);

        assert_eq!(
            slashable_vote_first.is_surround_vote(&slashable_vote_second, &spec),
            false
        );
    }

    ssz_tests!(SlashableAttestation);
    cached_tree_hash_tests!(SlashableAttestation);

    fn create_slashable_attestation(
        slot_factor: u64,
        source_epoch: u64,
        spec: &ChainSpec,
    ) -> SlashableAttestation {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut slashable_vote = SlashableAttestation::random_for_test(&mut rng);

        slashable_vote.data.slot = Slot::new(slot_factor * spec.slots_per_epoch);
        slashable_vote.data.source_epoch = Epoch::new(source_epoch);
        slashable_vote
    }
}
