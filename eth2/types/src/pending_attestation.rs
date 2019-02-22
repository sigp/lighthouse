use crate::test_utils::TestRandom;
use crate::{AttestationData, Bitfield, Slot};
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, Hashtree};

#[derive(Debug, Clone, PartialEq, Serialize, Encode, Decode, Hashtree)]
pub struct PendingAttestation {
    pub aggregation_bitfield: Bitfield,
    pub data: AttestationData,
    pub custody_bitfield: Bitfield,
    pub inclusion_slot: Slot,
}

impl<T: RngCore> TestRandom<T> for PendingAttestation {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            data: <_>::random_for_test(rng),
            aggregation_bitfield: <_>::random_for_test(rng),
            custody_bitfield: <_>::random_for_test(rng),
            inclusion_slot: <_>::random_for_test(rng),
        }
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
        let original = PendingAttestation::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root_internal() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = PendingAttestation::random_for_test(&mut rng);

        let result = original.hash_tree_root_internal();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
