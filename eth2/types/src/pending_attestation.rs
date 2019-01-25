use super::{AttestationData, Bitfield};
use crate::test_utils::TestRandom;
use rand::RngCore;
use ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};

#[derive(Debug, Clone, PartialEq)]
pub struct PendingAttestation {
    pub data: AttestationData,
    pub aggregation_bitfield: Bitfield,
    pub custody_bitfield: Bitfield,
    pub slot_included: u64,
}

impl Encodable for PendingAttestation {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.data);
        s.append(&self.aggregation_bitfield);
        s.append(&self.custody_bitfield);
        s.append(&self.slot_included);
    }
}

impl Decodable for PendingAttestation {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (data, i) = <_>::ssz_decode(bytes, i)?;
        let (aggregation_bitfield, i) = <_>::ssz_decode(bytes, i)?;
        let (custody_bitfield, i) = <_>::ssz_decode(bytes, i)?;
        let (slot_included, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                data,
                aggregation_bitfield,
                custody_bitfield,
                slot_included,
            },
            i,
        ))
    }
}

impl TreeHash for PendingAttestation {
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.data.hash_tree_root());
        result.append(&mut self.aggregation_bitfield.hash_tree_root());
        result.append(&mut self.custody_bitfield.hash_tree_root());
        result.append(&mut self.custody_bitfield.hash_tree_root());
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for PendingAttestation {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            data: <_>::random_for_test(rng),
            aggregation_bitfield: <_>::random_for_test(rng),
            custody_bitfield: <_>::random_for_test(rng),
            slot_included: <_>::random_for_test(rng),
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
        let original = PendingAttestation::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = PendingAttestation::random_for_test(&mut rng);

        let result = original.hash_tree_root();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
