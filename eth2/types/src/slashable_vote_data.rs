use super::AttestationData;
use crate::chain_spec::ChainSpec;
use crate::test_utils::TestRandom;
use bls::AggregateSignature;
use rand::RngCore;
use serde_derive::Serialize;
use ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};

#[derive(Debug, PartialEq, Clone, Serialize)]
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

impl Encodable for SlashableVoteData {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.custody_bit_0_indices);
        s.append_vec(&self.custody_bit_1_indices);
        s.append(&self.data);
        s.append(&self.aggregate_signature);
    }
}

impl Decodable for SlashableVoteData {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (custody_bit_0_indices, i) = <_>::ssz_decode(bytes, i)?;
        let (custody_bit_1_indices, i) = <_>::ssz_decode(bytes, i)?;
        let (data, i) = <_>::ssz_decode(bytes, i)?;
        let (aggregate_signature, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            SlashableVoteData {
                custody_bit_0_indices,
                custody_bit_1_indices,
                data,
                aggregate_signature,
            },
            i,
        ))
    }
}

impl TreeHash for SlashableVoteData {
    fn hash_tree_root_internal(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.custody_bit_0_indices.hash_tree_root_internal());
        result.append(&mut self.custody_bit_1_indices.hash_tree_root_internal());
        result.append(&mut self.data.hash_tree_root_internal());
        result.append(&mut self.aggregate_signature.hash_tree_root_internal());
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for SlashableVoteData {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            custody_bit_0_indices: <_>::random_for_test(rng),
            custody_bit_1_indices: <_>::random_for_test(rng),
            data: <_>::random_for_test(rng),
            aggregate_signature: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_spec::ChainSpec;
    use crate::slot_epoch::{Epoch, Slot};
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use ssz::ssz_encode;

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

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = SlashableVoteData::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root_internal() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = SlashableVoteData::random_for_test(&mut rng);

        let result = original.hash_tree_root_internal();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }

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
