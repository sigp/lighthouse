use super::ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};
use super::AttestationData;
use crate::test_utils::TestRandom;
use bls::AggregateSignature;
use rand::RngCore;

#[derive(Debug, PartialEq, Clone)]
pub struct SlashableVoteData {
    pub custody_bit_0_indices: Vec<u32>,
    pub custody_bit_1_indices: Vec<u32>,
    pub data: AttestationData,
    pub aggregate_signature: AggregateSignature,
}

impl Encodable for SlashableVoteData {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.custody_bit_0_indices);
        s.append_vec(&self.custody_bit_1_indices);
        s.append(&self.data);
        s.append(&self.aggregate_signature);
    }
}

impl Decodable for SlashableVoteData {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (custody_bit_0_indices, i) = <_>::ssz_decode(bytes, i)?;
        let (custody_bit_1_indices, i) = <_>::ssz_decode(bytes, i)?;
        let (data, i) = <_>::ssz_decode(bytes, i)?;
        let (aggregate_signature, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            SlashableVoteData {
                custody_bit_0_indices,
                custody_bit_1_indices,
                data,
                aggregate_signature,
            },
            i,
        ))
    }
}

impl TreeHash for SlashableVoteData {
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.custody_bit_0_indices.hash_tree_root());
        result.append(&mut self.custody_bit_1_indices.hash_tree_root());
        result.append(&mut self.data.hash_tree_root());
        result.append(&mut self.aggregate_signature.hash_tree_root());
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for SlashableVoteData {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            custody_bit_0_indices: <_>::random_for_test(rng),
            custody_bit_1_indices: <_>::random_for_test(rng),
            data: <_>::random_for_test(rng),
            aggregate_signature: <_>::random_for_test(rng),
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
        let original = SlashableVoteData::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = SlashableVoteData::random_for_test(&mut rng);

        let result = original.hash_tree_root();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
