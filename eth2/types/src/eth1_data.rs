use super::Hash256;
use crate::test_utils::TestRandom;
use rand::RngCore;
use ssz::{Decodable, DecodeError, Encodable, SszStream};

// Note: this is refer to as DepositRootVote in specs
#[derive(Debug, PartialEq, Clone, Default)]
pub struct Eth1Data {
    pub deposit_root: Hash256,
    pub block_hash: Hash256,
}

impl Encodable for Eth1Data {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.deposit_root);
        s.append(&self.block_hash);
    }
}

impl Decodable for Eth1Data {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (deposit_root, i) = <_>::ssz_decode(bytes, i)?;
        let (block_hash, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                deposit_root,
                block_hash,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for Eth1Data {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            deposit_root: <_>::random_for_test(rng),
            block_hash: <_>::random_for_test(rng),
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
        let original = Eth1Data::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
