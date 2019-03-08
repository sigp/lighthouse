use super::AttestationData;
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};

/// Used for pairing an attestation with a proof-of-custody.
///
/// Spec v0.4.0
#[derive(Debug, Clone, PartialEq, Default, Serialize, Encode, Decode, TreeHash)]
pub struct AttestationDataAndCustodyBit {
    pub data: AttestationData,
    pub custody_bit: bool,
}

impl<T: RngCore> TestRandom<T> for AttestationDataAndCustodyBit {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            data: <_>::random_for_test(rng),
            custody_bit: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use ssz::{ssz_encode, Decodable, TreeHash};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);

        let original = AttestationDataAndCustodyBit::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);

        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = AttestationDataAndCustodyBit::random_for_test(&mut rng);

        let result = original.hash_tree_root();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
