use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use crate::test_utils::TestRandom;
use rand::RngCore;

#[derive(Debug, PartialEq, Clone)]
pub struct ShardReassignmentRecord {
    pub validator_index: u64,
    pub shard: u64,
    pub slot: u64,
}

impl Encodable for ShardReassignmentRecord {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.validator_index);
        s.append(&self.shard);
        s.append(&self.slot);
    }
}

impl Decodable for ShardReassignmentRecord {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (validator_index, i) = <_>::ssz_decode(bytes, i)?;
        let (shard, i) = <_>::ssz_decode(bytes, i)?;
        let (slot, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                validator_index,
                shard,
                slot,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for ShardReassignmentRecord {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            validator_index: <_>::random_for_test(rng),
            shard: <_>::random_for_test(rng),
            slot: <_>::random_for_test(rng),
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
        let original = ShardReassignmentRecord::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
