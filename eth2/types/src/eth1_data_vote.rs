use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::Eth1Data;
use crate::test_utils::TestRandom;
use rand::RngCore;

// Note: this is refer to as DepositRootVote in specs
#[derive(Debug, PartialEq, Clone, Default)]
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
    use super::super::ssz::ssz_encode;
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = Eth1DataVote::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
