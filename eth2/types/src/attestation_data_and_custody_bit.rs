use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::AttestationData;
use crate::test_utils::TestRandom;
use rand::RngCore;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttestationDataAndCustodyBit {
    pub data: AttestationData,
    pub custody_bit: bool,
}

impl Encodable for AttestationDataAndCustodyBit {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.data);
        // TODO: deal with bools
    }
}

impl Decodable for AttestationDataAndCustodyBit {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (data, i) = <_>::ssz_decode(bytes, i)?;
        let custody_bit = false;

        let attestation_data_and_custody_bit = AttestationDataAndCustodyBit { data, custody_bit };

        Ok((attestation_data_and_custody_bit, i))
    }
}

impl<T: RngCore> TestRandom<T> for AttestationDataAndCustodyBit {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            data: <_>::random_for_test(rng),
            // TODO: deal with bools
            custody_bit: false,
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::ssz::ssz_encode;
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);

        let original = AttestationDataAndCustodyBit::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);

        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
