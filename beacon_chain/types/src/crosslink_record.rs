use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::Hash256;
use crate::test_utils::TestRandom;
use rand::RngCore;

#[derive(Clone, Debug, PartialEq)]
pub struct CrosslinkRecord {
    pub slot: u64,
    pub shard_block_root: Hash256,
}

impl CrosslinkRecord {
    /// Generates a new instance where `dynasty` and `hash` are both zero.
    pub fn zero() -> Self {
        Self {
            slot: 0,
            shard_block_root: Hash256::zero(),
        }
    }
}

impl Encodable for CrosslinkRecord {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.shard_block_root);
    }
}

impl Decodable for CrosslinkRecord {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slot, i) = <_>::ssz_decode(bytes, i)?;
        let (shard_block_root, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                slot,
                shard_block_root,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for CrosslinkRecord {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            slot: <_>::random_for_test(rng),
            shard_block_root: <_>::random_for_test(rng),
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
        let original = CrosslinkRecord::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
