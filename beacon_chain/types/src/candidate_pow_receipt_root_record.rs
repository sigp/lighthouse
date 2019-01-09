use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::Hash256;
use crate::test_utils::TestRandom;
use rand::RngCore;

#[derive(Debug, PartialEq, Clone)]
pub struct CandidatePoWReceiptRootRecord {
    pub candidate_pow_receipt_root: Hash256,
    pub votes: u64,
}

impl Encodable for CandidatePoWReceiptRootRecord {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.candidate_pow_receipt_root);
        s.append(&self.votes);
    }
}

impl Decodable for CandidatePoWReceiptRootRecord {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (candidate_pow_receipt_root, i) = <_>::ssz_decode(bytes, i)?;
        let (votes, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                candidate_pow_receipt_root,
                votes,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for CandidatePoWReceiptRootRecord {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            candidate_pow_receipt_root: <_>::random_for_test(rng),
            votes: <_>::random_for_test(rng),
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
        let original = CandidatePoWReceiptRootRecord::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
