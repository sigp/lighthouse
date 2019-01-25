use super::ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};
use super::{DepositData, Hash256};
use crate::test_utils::TestRandom;
use rand::RngCore;

#[derive(Debug, PartialEq, Clone)]
pub struct Deposit {
    pub merkle_branch: Vec<Hash256>,
    pub merkle_tree_index: u64,
    pub deposit_data: DepositData,
}

impl Encodable for Deposit {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.merkle_branch);
        s.append(&self.merkle_tree_index);
        s.append(&self.deposit_data);
    }
}

impl Decodable for Deposit {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (merkle_branch, i) = <_>::ssz_decode(bytes, i)?;
        let (merkle_tree_index, i) = <_>::ssz_decode(bytes, i)?;
        let (deposit_data, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                merkle_branch,
                merkle_tree_index,
                deposit_data,
            },
            i,
        ))
    }
}

impl TreeHash for Deposit {
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.merkle_branch.hash_tree_root());
        result.append(&mut self.merkle_tree_index.hash_tree_root());
        result.append(&mut self.deposit_data.hash_tree_root());
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for Deposit {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            merkle_branch: <_>::random_for_test(rng),
            merkle_tree_index: <_>::random_for_test(rng),
            deposit_data: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = Deposit::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = Deposit::random_for_test(&mut rng);

        let result = original.hash_tree_root();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
