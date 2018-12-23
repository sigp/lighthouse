use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::ProposalSignedData;
use crate::random::TestRandom;
use bls::Signature;
use rand::RngCore;

#[derive(Debug, PartialEq, Clone, Default)]
pub struct ProposerSlashing {
    pub proposer_index: u32,
    pub proposal_data_1: ProposalSignedData,
    pub proposal_signature_1: Signature,
    pub proposal_data_2: ProposalSignedData,
    pub proposal_signature_2: Signature,
}

impl Encodable for ProposerSlashing {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.proposer_index);
        s.append(&self.proposal_data_1);
        s.append(&self.proposal_signature_1);
        s.append(&self.proposal_data_2);
        s.append(&self.proposal_signature_2);
    }
}

impl Decodable for ProposerSlashing {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (proposer_index, i) = <_>::ssz_decode(bytes, i)?;
        let (proposal_data_1, i) = <_>::ssz_decode(bytes, i)?;
        let (proposal_signature_1, i) = <_>::ssz_decode(bytes, i)?;
        let (proposal_data_2, i) = <_>::ssz_decode(bytes, i)?;
        let (proposal_signature_2, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            ProposerSlashing {
                proposer_index,
                proposal_data_1,
                proposal_signature_1,
                proposal_data_2,
                proposal_signature_2,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for ProposerSlashing {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            proposer_index: <_>::random_for_test(rng),
            proposal_data_1: <_>::random_for_test(rng),
            proposal_signature_1: <_>::random_for_test(rng),
            proposal_data_2: <_>::random_for_test(rng),
            proposal_signature_2: <_>::random_for_test(rng),
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
        let original = ProposerSlashing::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
