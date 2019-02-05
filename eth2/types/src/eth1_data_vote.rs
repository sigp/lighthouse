use super::Eth1Data;
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::Serialize;
use ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};

// Note: this is refer to as DepositRootVote in specs
#[derive(Debug, PartialEq, Clone, Default, Serialize)]
pub struct Eth1DataVote {
    pub eth1_data: Eth1Data,
    pub vote_count: u64,
}

impl Encodable for Eth1DataVote {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.eth1_data);
        s.append(&self.vote_count);
    }
}

impl Decodable for Eth1DataVote {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (eth1_data, i) = <_>::ssz_decode(bytes, i)?;
        let (vote_count, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                eth1_data,
                vote_count,
            },
            i,
        ))
    }
}

impl TreeHash for Eth1DataVote {
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.eth1_data.hash_tree_root());
        result.append(&mut self.vote_count.hash_tree_root());
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for Eth1DataVote {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            eth1_data: <_>::random_for_test(rng),
            vote_count: <_>::random_for_test(rng),
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
        let original = Eth1DataVote::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = Eth1DataVote::random_for_test(&mut rng);

        let result = original.hash_tree_root();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
