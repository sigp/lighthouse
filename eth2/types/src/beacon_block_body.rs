use super::{Attestation, AttesterSlashing, Deposit, Exit, ProposerSlashing};
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::Serialize;
use ssz::{hash, TreeHash};
use ssz_derive::{Decode, Encode};

#[derive(Debug, PartialEq, Clone, Default, Serialize, Encode, Decode)]
pub struct BeaconBlockBody {
    pub proposer_slashings: Vec<ProposerSlashing>,
    pub attester_slashings: Vec<AttesterSlashing>,
    pub attestations: Vec<Attestation>,
    pub deposits: Vec<Deposit>,
    pub exits: Vec<Exit>,
}

impl TreeHash for BeaconBlockBody {
    fn hash_tree_root_internal(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.proposer_slashings.hash_tree_root_internal());
        result.append(&mut self.attester_slashings.hash_tree_root_internal());
        result.append(&mut self.attestations.hash_tree_root_internal());
        result.append(&mut self.deposits.hash_tree_root_internal());
        result.append(&mut self.exits.hash_tree_root_internal());
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for BeaconBlockBody {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            proposer_slashings: <_>::random_for_test(rng),
            attester_slashings: <_>::random_for_test(rng),
            attestations: <_>::random_for_test(rng),
            deposits: <_>::random_for_test(rng),
            exits: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use ssz::{ssz_encode, Decodable};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = BeaconBlockBody::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root_internal() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = BeaconBlockBody::random_for_test(&mut rng);

        let result = original.hash_tree_root_internal();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
