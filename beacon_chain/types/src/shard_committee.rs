use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use crate::test_utils::TestRandom;
use rand::RngCore;

#[derive(Clone, Debug, PartialEq)]
pub struct ShardCommittee {
    pub shard: u64,
    pub committee: Vec<usize>,
}

impl Encodable for ShardCommittee {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.shard);
        s.append(&self.committee);
    }
}

impl Decodable for ShardCommittee {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (shard, i) = <_>::ssz_decode(bytes, i)?;
        let (committee, i) = <_>::ssz_decode(bytes, i)?;

        Ok((Self { shard, committee }, i))
    }
}

impl<T: RngCore> TestRandom<T> for ShardCommittee {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            shard: <_>::random_for_test(rng),
            committee: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::*;
    use crate::test_utils::TestRandom;
    use rand::{prng::XorShiftRng, SeedableRng};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = ShardCommittee::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
