use super::AttestationData;
use crate::chain_spec::ChainSpec;
use crate::test_utils::TestRandom;
use bls::AggregateSignature;
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

#[derive(Debug, PartialEq, Clone, Serialize, Encode, Decode, TreeHash, TestRandom)]
pub struct SlashableVoteData {
    pub custody_bit_0_indices: Vec<u32>,
    pub custody_bit_1_indices: Vec<u32>,
    pub data: AttestationData,
    pub aggregate_signature: AggregateSignature,
}

impl SlashableVoteData {
    /// Check if ``attestation_data_1`` and ``attestation_data_2`` have the same target.
    ///
    /// Spec v0.3.0
    pub fn is_double_vote(&self, other: &SlashableVoteData, spec: &ChainSpec) -> bool {
        self.data.slot.epoch(spec.epoch_length) == other.data.slot.epoch(spec.epoch_length)
    }

    /// Check if ``attestation_data_1`` surrounds ``attestation_data_2``.
    ///
    /// Spec v0.3.0
    pub fn is_surround_vote(&self, other: &SlashableVoteData, spec: &ChainSpec) -> bool {
        let source_epoch_1 = self.data.justified_epoch;
        let source_epoch_2 = other.data.justified_epoch;
        let target_epoch_1 = self.data.slot.epoch(spec.epoch_length);
        let target_epoch_2 = other.data.slot.epoch(spec.epoch_length);

        (source_epoch_1 < source_epoch_2) && (target_epoch_2 < target_epoch_1)
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
        let slashable_vote_first = create_slashable_vote_data(1, 1, &spec);
        let slashable_vote_second = create_slashable_vote_data(1, 1, &spec);

        assert_eq!(
            slashable_vote_first.is_double_vote(&slashable_vote_second, &spec),
            true
        )
    }

    #[test]
    pub fn test_is_double_vote_false() {
        let spec = ChainSpec::foundation();
        let slashable_vote_first = create_slashable_vote_data(1, 1, &spec);
        let slashable_vote_second = create_slashable_vote_data(2, 1, &spec);

        assert_eq!(
            slashable_vote_first.is_double_vote(&slashable_vote_second, &spec),
            false
        );
    }

    #[test]
    pub fn test_is_surround_vote_true() {
        let spec = ChainSpec::foundation();
        let slashable_vote_first = create_slashable_vote_data(2, 1, &spec);
        let slashable_vote_second = create_slashable_vote_data(1, 2, &spec);

        assert_eq!(
            slashable_vote_first.is_surround_vote(&slashable_vote_second, &spec),
            true
        );
    }

    #[test]
    pub fn test_is_surround_vote_true_realistic() {
        let spec = ChainSpec::foundation();
        let slashable_vote_first = create_slashable_vote_data(4, 1, &spec);
        let slashable_vote_second = create_slashable_vote_data(3, 2, &spec);

        assert_eq!(
            slashable_vote_first.is_surround_vote(&slashable_vote_second, &spec),
            true
        );
    }

    #[test]
    pub fn test_is_surround_vote_false_source_epoch_fails() {
        let spec = ChainSpec::foundation();
        let slashable_vote_first = create_slashable_vote_data(2, 2, &spec);
        let slashable_vote_second = create_slashable_vote_data(1, 1, &spec);

        assert_eq!(
            slashable_vote_first.is_surround_vote(&slashable_vote_second, &spec),
            false
        );
    }

    #[test]
    pub fn test_is_surround_vote_false_target_epoch_fails() {
        let spec = ChainSpec::foundation();
        let slashable_vote_first = create_slashable_vote_data(1, 1, &spec);
        let slashable_vote_second = create_slashable_vote_data(2, 2, &spec);

        assert_eq!(
            slashable_vote_first.is_surround_vote(&slashable_vote_second, &spec),
            false
        );
    }

    ssz_tests!(SlashableVoteData);

    fn create_slashable_vote_data(
        slot_factor: u64,
        justified_epoch: u64,
        spec: &ChainSpec,
    ) -> SlashableVoteData {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut slashable_vote = SlashableVoteData::random_for_test(&mut rng);

        slashable_vote.data.slot = Slot::new(slot_factor * spec.epoch_length);
        slashable_vote.data.justified_epoch = Epoch::new(justified_epoch);
        slashable_vote
    }
}
