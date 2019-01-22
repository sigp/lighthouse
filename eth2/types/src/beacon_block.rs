use super::ssz::{ssz_encode, Decodable, DecodeError, Encodable, SszStream};
use super::{BeaconBlockBody, Hash256};
use crate::test_utils::TestRandom;
use bls::Signature;
use hashing::canonical_hash;
use rand::RngCore;

#[derive(Debug, PartialEq, Clone)]
pub struct BeaconBlock {
    pub slot: u64,
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub randao_reveal: Hash256,
    pub candidate_pow_receipt_root: Hash256,
    pub signature: Signature,
    pub body: BeaconBlockBody,
}

impl BeaconBlock {
    pub fn canonical_root(&self) -> Hash256 {
        // TODO: implement tree hashing.
        // https://github.com/sigp/lighthouse/issues/70
        Hash256::from(&canonical_hash(&ssz_encode(self))[..])
    }
}

impl Encodable for BeaconBlock {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.parent_root);
        s.append(&self.state_root);
        s.append(&self.randao_reveal);
        s.append(&self.candidate_pow_receipt_root);
        s.append(&self.signature);
        s.append(&self.body);
    }
}

impl Decodable for BeaconBlock {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slot, i) = <_>::ssz_decode(bytes, i)?;
        let (parent_root, i) = <_>::ssz_decode(bytes, i)?;
        let (state_root, i) = <_>::ssz_decode(bytes, i)?;
        let (randao_reveal, i) = <_>::ssz_decode(bytes, i)?;
        let (candidate_pow_receipt_root, i) = <_>::ssz_decode(bytes, i)?;
        let (signature, i) = <_>::ssz_decode(bytes, i)?;
        let (body, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                slot,
                parent_root,
                state_root,
                randao_reveal,
                candidate_pow_receipt_root,
                signature,
                body,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for BeaconBlock {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            slot: <_>::random_for_test(rng),
            parent_root: <_>::random_for_test(rng),
            state_root: <_>::random_for_test(rng),
            randao_reveal: <_>::random_for_test(rng),
            candidate_pow_receipt_root: <_>::random_for_test(rng),
            signature: <_>::random_for_test(rng),
            body: <_>::random_for_test(rng),
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
        let original = BeaconBlock::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
