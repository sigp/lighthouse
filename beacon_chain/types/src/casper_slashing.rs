use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::SlashableVoteData;
use crate::random::TestRandom;
use rand::RngCore;

#[derive(Debug, PartialEq, Clone, Default)]
pub struct CasperSlashing {
    pub slashable_vote_data_1: SlashableVoteData,
    pub slashable_vote_data_2: SlashableVoteData,
}

impl Encodable for CasperSlashing {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slashable_vote_data_1);
        s.append(&self.slashable_vote_data_2);
    }
}

impl Decodable for CasperSlashing {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slashable_vote_data_1, i) = <_>::ssz_decode(bytes, i)?;
        let (slashable_vote_data_2, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            CasperSlashing {
                slashable_vote_data_1,
                slashable_vote_data_2,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for CasperSlashing {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            slashable_vote_data_1: <_>::random_for_test(rng),
            slashable_vote_data_2: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::*;
    use crate::random::TestRandom;
    use rand::{prng::XorShiftRng, SeedableRng};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = CasperSlashing::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
