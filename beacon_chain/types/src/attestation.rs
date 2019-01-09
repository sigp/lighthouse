use super::bls::AggregateSignature;
use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::{AttestationData, Bitfield};
use crate::test_utils::TestRandom;
use rand::RngCore;

#[derive(Debug, Clone, PartialEq)]
pub struct Attestation {
    pub data: AttestationData,
    pub participation_bitfield: Bitfield,
    pub custody_bitfield: Bitfield,
    pub aggregate_sig: AggregateSignature,
}

impl Encodable for Attestation {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.data);
        s.append(&self.participation_bitfield);
        s.append(&self.custody_bitfield);
        s.append(&self.aggregate_sig);
    }
}

impl Decodable for Attestation {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (data, i) = AttestationData::ssz_decode(bytes, i)?;
        let (participation_bitfield, i) = Bitfield::ssz_decode(bytes, i)?;
        let (custody_bitfield, i) = Bitfield::ssz_decode(bytes, i)?;
        let (aggregate_sig, i) = AggregateSignature::ssz_decode(bytes, i)?;

        let attestation_record = Self {
            data,
            participation_bitfield,
            custody_bitfield,
            aggregate_sig,
        };
        Ok((attestation_record, i))
    }
}

impl Attestation {
    pub fn zero() -> Self {
        Self {
            data: AttestationData::zero(),
            participation_bitfield: Bitfield::new(),
            custody_bitfield: Bitfield::new(),
            aggregate_sig: AggregateSignature::new(),
        }
    }
}

impl<T: RngCore> TestRandom<T> for Attestation {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            data: <_>::random_for_test(rng),
            participation_bitfield: <_>::random_for_test(rng),
            custody_bitfield: <_>::random_for_test(rng),
            aggregate_sig: <_>::random_for_test(rng),
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
        let original = Attestation::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
