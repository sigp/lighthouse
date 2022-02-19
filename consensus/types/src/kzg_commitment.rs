use crate::test_utils::TestRandom;
use crate::*;
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

//TODO: is there a way around this newtype
#[derive(Derivative, Debug, Clone, Serialize, Deserialize)]
#[derivative(PartialEq, Eq, Hash)]
pub struct KZGCommitment(#[serde(with = "BigArray")] [u8; 48]);
impl TreeHash for KZGCommitment {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <[u8; 48] as TreeHash>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <[u8; 48] as TreeHash>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl TestRandom for KZGCommitment {
    fn random_for_test(rng: &mut impl rand::RngCore) -> Self {
        KZGCommitment(<[u8; 48] as TestRandom>::random_for_test(rng))
    }
}

impl Decode for KZGCommitment {
    fn is_ssz_fixed_len() -> bool {
        <[u8; 48] as Decode>::is_ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 48] as Decode>::from_ssz_bytes(bytes).map(KZGCommitment)
    }
}

impl Encode for KZGCommitment {
    fn is_ssz_fixed_len() -> bool {
        <[u8; 48] as Encode>::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }
}
