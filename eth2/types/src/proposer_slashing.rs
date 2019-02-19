use super::ProposalSignedData;
use crate::test_utils::TestRandom;
use bls::Signature;
use rand::RngCore;
use serde_derive::Serialize;
use ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};
use ssz_derive::{Decode, Encode};

#[derive(Debug, PartialEq, Clone, Serialize, Encode, Decode)]
pub struct ProposerSlashing {
    pub proposer_index: u64,
    pub proposal_data_1: ProposalSignedData,
    pub proposal_signature_1: Signature,
    pub proposal_data_2: ProposalSignedData,
    pub proposal_signature_2: Signature,
}

impl TreeHash for ProposerSlashing {
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.proposer_index.hash_tree_root());
        result.append(&mut self.proposal_data_1.hash_tree_root());
        result.append(&mut self.proposal_signature_1.hash_tree_root());
        result.append(&mut self.proposal_data_2.hash_tree_root());
        result.append(&mut self.proposal_signature_2.hash_tree_root());
        hash(&result)
    }
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
    use ssz::ssz_encode;

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = ProposerSlashing::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = ProposerSlashing::random_for_test(&mut rng);

        let result = original.hash_tree_root();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
