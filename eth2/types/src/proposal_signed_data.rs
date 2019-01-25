use super::Hash256;
use crate::test_utils::TestRandom;
use rand::RngCore;
use ssz::{Decodable, DecodeError, Encodable, SszStream};

#[derive(Debug, PartialEq, Clone, Default)]
pub struct ProposalSignedData {
    pub slot: u64,
    pub shard: u64,
    pub block_root: Hash256,
}

impl Encodable for ProposalSignedData {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.shard);
        s.append(&self.block_root);
    }
}

impl Decodable for ProposalSignedData {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slot, i) = <_>::ssz_decode(bytes, i)?;
        let (shard, i) = <_>::ssz_decode(bytes, i)?;
        let (block_root, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            ProposalSignedData {
                slot,
                shard,
                block_root,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for ProposalSignedData {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            slot: <_>::random_for_test(rng),
            shard: <_>::random_for_test(rng),
            block_root: <_>::random_for_test(rng),
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
        let original = ProposalSignedData::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
