use super::{AttestationData, Bitfield};
use crate::test_utils::TestRandom;
use bls::AggregateSignature;
use rand::RngCore;
use ssz::{Decodable, DecodeError, Encodable, SszStream};

#[derive(Debug, Clone, PartialEq)]
pub struct Attestation {
    pub data: AttestationData,
    pub aggregation_bitfield: Bitfield,
    pub custody_bitfield: Bitfield,
    pub aggregate_signature: AggregateSignature,
}

impl Encodable for Attestation {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.data);
        s.append(&self.aggregation_bitfield);
        s.append(&self.custody_bitfield);
        s.append(&self.aggregate_signature);
    }
}

impl Decodable for Attestation {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (data, i) = AttestationData::ssz_decode(bytes, i)?;
        let (aggregation_bitfield, i) = Bitfield::ssz_decode(bytes, i)?;
        let (custody_bitfield, i) = Bitfield::ssz_decode(bytes, i)?;
        let (aggregate_signature, i) = AggregateSignature::ssz_decode(bytes, i)?;

        let attestation_record = Self {
            data,
            aggregation_bitfield,
            custody_bitfield,
            aggregate_signature,
        };
        Ok((attestation_record, i))
    }
}

impl Attestation {
    pub fn zero() -> Self {
        Self {
            data: AttestationData::zero(),
            aggregation_bitfield: Bitfield::new(),
            custody_bitfield: Bitfield::new(),
            aggregate_signature: AggregateSignature::new(),
        }
    }
}

impl<T: RngCore> TestRandom<T> for Attestation {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            data: <_>::random_for_test(rng),
            aggregation_bitfield: <_>::random_for_test(rng),
            custody_bitfield: <_>::random_for_test(rng),
            aggregate_signature: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ssz::ssz_encode;
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
