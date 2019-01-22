use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::{AttestationData, Bitfield};
use crate::test_utils::TestRandom;
use rand::RngCore;

#[derive(Debug, Clone, PartialEq)]
pub struct PendingAttestationRecord {
    pub data: AttestationData,
    pub participation_bitfield: Bitfield,
    pub custody_bitfield: Bitfield,
    pub slot_included: u64,
}

impl Encodable for PendingAttestationRecord {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.data);
        s.append(&self.participation_bitfield);
        s.append(&self.custody_bitfield);
        s.append(&self.slot_included);
    }
}

impl Decodable for PendingAttestationRecord {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (data, i) = <_>::ssz_decode(bytes, i)?;
        let (participation_bitfield, i) = <_>::ssz_decode(bytes, i)?;
        let (custody_bitfield, i) = <_>::ssz_decode(bytes, i)?;
        let (slot_included, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                data,
                participation_bitfield,
                custody_bitfield,
                slot_included,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for PendingAttestationRecord {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            data: <_>::random_for_test(rng),
            participation_bitfield: <_>::random_for_test(rng),
            custody_bitfield: <_>::random_for_test(rng),
            slot_included: <_>::random_for_test(rng),
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
        let original = PendingAttestationRecord::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
