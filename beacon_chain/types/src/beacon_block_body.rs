use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::{Attestation, CasperSlashing, Deposit, Exit, ProposerSlashing};
use crate::random::TestRandom;
use rand::RngCore;

#[derive(Debug, PartialEq, Clone, Default)]
pub struct BeaconBlockBody {
    pub proposer_slashings: Vec<ProposerSlashing>,
    pub casper_slashings: Vec<CasperSlashing>,
    pub attestations: Vec<Attestation>,
    pub deposits: Vec<Deposit>,
    pub exits: Vec<Exit>,
}

impl Encodable for BeaconBlockBody {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.proposer_slashings);
        s.append_vec(&self.casper_slashings);
        s.append_vec(&self.attestations);
        s.append_vec(&self.deposits);
        s.append_vec(&self.exits);
    }
}

impl Decodable for BeaconBlockBody {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (proposer_slashings, i) = <_>::ssz_decode(bytes, i)?;
        let (casper_slashings, i) = <_>::ssz_decode(bytes, i)?;
        let (attestations, i) = <_>::ssz_decode(bytes, i)?;
        let (deposits, i) = <_>::ssz_decode(bytes, i)?;
        let (exits, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                proposer_slashings,
                casper_slashings,
                attestations,
                deposits,
                exits,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for BeaconBlockBody {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            proposer_slashings: <_>::random_for_test(rng),
            casper_slashings: <_>::random_for_test(rng),
            attestations: <_>::random_for_test(rng),
            deposits: <_>::random_for_test(rng),
            exits: <_>::random_for_test(rng),
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
        let original = BeaconBlockBody::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
