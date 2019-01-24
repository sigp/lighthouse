use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::Hash256;
use crate::test_utils::TestRandom;
use rand::RngCore;

#[derive(Clone, Debug, PartialEq)]
pub struct Crosslink {
    pub slot: u64,
    pub shard_block_root: Hash256,
}

impl Crosslink {
    /// Generates a new instance where `dynasty` and `hash` are both zero.
    pub fn zero() -> Self {
        Self {
            slot: 0,
            shard_block_root: Hash256::zero(),
        }
    }
}

impl Encodable for Crosslink {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.shard_block_root);
    }
}

impl Decodable for Crosslink {
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

impl<T: RngCore> TestRandom<T> for Crosslink {
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
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = Crosslink::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
