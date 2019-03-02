use crate::{test_utils::TestRandom, AggregateSignature, AttestationData, Bitfield, ChainSpec};
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

#[derive(Debug, PartialEq, Clone, Serialize, Encode, Decode, TreeHash, TestRandom)]
pub struct SlashableAttestation {
    pub validator_indices: Vec<u64>,
    pub data: AttestationData,
    pub custody_bitfield: Bitfield,
    pub aggregate_signature: AggregateSignature,
}

impl SlashableAttestation {
    /// Check if ``attestation_data_1`` and ``attestation_data_2`` have the same target.
    ///
    /// Spec v0.3.0
    pub fn is_double_vote(&self, other: &SlashableAttestation, spec: &ChainSpec) -> bool {
        self.data.slot.epoch(spec.epoch_length) == other.data.slot.epoch(spec.epoch_length)
    }

    /// Check if ``attestation_data_1`` surrounds ``attestation_data_2``.
    ///
    /// Spec v0.3.0
    pub fn is_surround_vote(&self, other: &SlashableAttestation, spec: &ChainSpec) -> bool {
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
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use ssz::{ssz_encode, Decodable, TreeHash};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = SlashableAttestation::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root_internal() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = SlashableAttestation::random_for_test(&mut rng);

        let result = original.hash_tree_root_internal();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
