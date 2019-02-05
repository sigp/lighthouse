use super::{Attestation, CasperSlashing, Deposit, Exit, ProposerSlashing};
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::Serialize;
use ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};

// The following types are just dummy classes as they will not be defined until
// Phase 1 (Sharding phase)
type CustodyReseed = usize;
type CustodyChallenge = usize;
type CustodyResponse = usize;

#[derive(Debug, PartialEq, Clone, Default, Serialize)]
pub struct BeaconBlockBody {
    pub proposer_slashings: Vec<ProposerSlashing>,
    pub casper_slashings: Vec<CasperSlashing>,
    pub attestations: Vec<Attestation>,
    pub custody_reseeds: Vec<CustodyReseed>,
    pub custody_challenges: Vec<CustodyChallenge>,
    pub custody_responses: Vec<CustodyResponse>,
    pub deposits: Vec<Deposit>,
    pub exits: Vec<Exit>,
}

impl Encodable for BeaconBlockBody {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.proposer_slashings);
        s.append_vec(&self.casper_slashings);
        s.append_vec(&self.attestations);
        s.append_vec(&self.custody_reseeds);
        s.append_vec(&self.custody_challenges);
        s.append_vec(&self.custody_responses);
        s.append_vec(&self.deposits);
        s.append_vec(&self.exits);
    }
}

impl Decodable for BeaconBlockBody {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (proposer_slashings, i) = <_>::ssz_decode(bytes, i)?;
        let (casper_slashings, i) = <_>::ssz_decode(bytes, i)?;
        let (attestations, i) = <_>::ssz_decode(bytes, i)?;
        let (custody_reseeds, i) = <_>::ssz_decode(bytes, i)?;
        let (custody_challenges, i) = <_>::ssz_decode(bytes, i)?;
        let (custody_responses, i) = <_>::ssz_decode(bytes, i)?;
        let (deposits, i) = <_>::ssz_decode(bytes, i)?;
        let (exits, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                proposer_slashings,
                casper_slashings,
                attestations,
                custody_reseeds,
                custody_challenges,
                custody_responses,
                deposits,
                exits,
            },
            i,
        ))
    }
}

impl TreeHash for BeaconBlockBody {
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.proposer_slashings.hash_tree_root());
        result.append(&mut self.casper_slashings.hash_tree_root());
        result.append(&mut self.attestations.hash_tree_root());
        result.append(&mut self.custody_reseeds.hash_tree_root());
        result.append(&mut self.custody_challenges.hash_tree_root());
        result.append(&mut self.custody_responses.hash_tree_root());
        result.append(&mut self.deposits.hash_tree_root());
        result.append(&mut self.exits.hash_tree_root());
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for BeaconBlockBody {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            proposer_slashings: <_>::random_for_test(rng),
            casper_slashings: <_>::random_for_test(rng),
            attestations: <_>::random_for_test(rng),
            custody_reseeds: <_>::random_for_test(rng),
            custody_challenges: <_>::random_for_test(rng),
            custody_responses: <_>::random_for_test(rng),
            deposits: <_>::random_for_test(rng),
            exits: <_>::random_for_test(rng),
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
        let original = BeaconBlockBody::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = BeaconBlockBody::random_for_test(&mut rng);

        let result = original.hash_tree_root();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
