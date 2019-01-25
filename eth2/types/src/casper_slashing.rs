use super::SlashableVoteData;
use crate::test_utils::TestRandom;
use rand::RngCore;
use ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};

#[derive(Debug, PartialEq, Clone)]
pub struct CasperSlashing {
    pub slashable_vote_data_1: SlashableVoteData,
    pub slashable_vote_data_2: SlashableVoteData,
}

impl Encodable for CasperSlashing {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slashable_vote_data_1);
        s.append(&self.slashable_vote_data_2);
    }
}

impl Decodable for CasperSlashing {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slashable_vote_data_1, i) = <_>::ssz_decode(bytes, i)?;
        let (slashable_vote_data_2, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            CasperSlashing {
                slashable_vote_data_1,
                slashable_vote_data_2,
            },
            i,
        ))
    }
}

impl TreeHash for CasperSlashing {
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.slashable_vote_data_1.hash_tree_root());
        result.append(&mut self.slashable_vote_data_2.hash_tree_root());
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for CasperSlashing {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            slashable_vote_data_1: <_>::random_for_test(rng),
            slashable_vote_data_2: <_>::random_for_test(rng),
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
        let original = CasperSlashing::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = CasperSlashing::random_for_test(&mut rng);

        let result = original.hash_tree_root();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
