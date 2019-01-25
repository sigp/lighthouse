use crate::test_utils::TestRandom;
use rand::RngCore;
use ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Fork {
    pub pre_fork_version: u64,
    pub post_fork_version: u64,
    pub fork_slot: u64,
}

impl Encodable for Fork {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.pre_fork_version);
        s.append(&self.post_fork_version);
        s.append(&self.fork_slot);
    }
}

impl Decodable for Fork {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (pre_fork_version, i) = <_>::ssz_decode(bytes, i)?;
        let (post_fork_version, i) = <_>::ssz_decode(bytes, i)?;
        let (fork_slot, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                pre_fork_version,
                post_fork_version,
                fork_slot,
            },
            i,
        ))
    }
}

impl TreeHash for Fork {
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.pre_fork_version.hash_tree_root());
        result.append(&mut self.post_fork_version.hash_tree_root());
        result.append(&mut self.fork_slot.hash_tree_root());
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for Fork {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            pre_fork_version: <_>::random_for_test(rng),
            post_fork_version: <_>::random_for_test(rng),
            fork_slot: <_>::random_for_test(rng),
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
        let original = Fork::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = Fork::random_for_test(&mut rng);

        let result = original.hash_tree_root();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
