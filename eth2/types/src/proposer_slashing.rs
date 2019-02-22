use super::ProposalSignedData;
use crate::test_utils::TestRandom;
use bls::Signature;
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, Hashtree};

#[derive(Debug, PartialEq, Clone, Serialize, Encode, Decode, Hashtree)]
pub struct ProposerSlashing {
    pub proposer_index: u64,
    pub proposal_data_1: ProposalSignedData,
    pub proposal_signature_1: Signature,
    pub proposal_data_2: ProposalSignedData,
    pub proposal_signature_2: Signature,
}

impl<T: RngCore> TestRandom<T> for ProposerSlashing {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            proposer_index: <_>::random_for_test(rng),
            proposal_data_1: <_>::random_for_test(rng),
            proposal_signature_1: <_>::random_for_test(rng),
            proposal_data_2: <_>::random_for_test(rng),
            proposal_signature_2: <_>::random_for_test(rng),
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
        let original = ProposerSlashing::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root_internal() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = ProposerSlashing::random_for_test(&mut rng);

        let result = original.hash_tree_root_internal();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
