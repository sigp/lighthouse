use crate::{EthSpec, Uint256};
use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use tree_hash::TreeHash;

#[derive(Default, Debug, PartialEq, Hash, Clone, Copy, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlsFieldElement(pub Uint256);


impl Encode for BlsFieldElement {
    fn is_ssz_fixed_len() -> bool {
        <Uint256 as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <Uint256 as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }
}

impl Decode for BlsFieldElement {
    fn is_ssz_fixed_len() -> bool {
        <Uint256 as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <Uint256 as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        <Uint256 as Decode>::from_ssz_bytes(bytes).map(Self)
    }
}

impl TreeHash for BlsFieldElement {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <Uint256>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <Uint256>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}
