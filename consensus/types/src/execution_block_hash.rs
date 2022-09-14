use crate::test_utils::TestRandom;
use crate::Hash256;
use derivative::Derivative;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use std::fmt;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Default, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash, Derivative)]
#[derivative(Debug = "transparent")]
#[serde(transparent)]
pub struct ExecutionBlockHash(Hash256);

impl ExecutionBlockHash {
    pub fn zero() -> Self {
        Self(Hash256::zero())
    }

    pub fn repeat_byte(b: u8) -> Self {
        Self(Hash256::repeat_byte(b))
    }

    pub fn from_root(root: Hash256) -> Self {
        Self(root)
    }

    pub fn into_root(self) -> Hash256 {
        self.0
    }
}

impl Encode for ExecutionBlockHash {
    fn is_ssz_fixed_len() -> bool {
        <Hash256 as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <Hash256 as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }
}

impl Decode for ExecutionBlockHash {
    fn is_ssz_fixed_len() -> bool {
        <Hash256 as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <Hash256 as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Hash256::from_ssz_bytes(bytes).map(Self)
    }
}

impl tree_hash::TreeHash for ExecutionBlockHash {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        Hash256::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        Hash256::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl TestRandom for ExecutionBlockHash {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        Self(Hash256::random_for_test(rng))
    }
}

impl std::str::FromStr for ExecutionBlockHash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hash256::from_str(s)
            .map(Self)
            .map_err(|e| format!("{:?}", e))
    }
}

impl fmt::Display for ExecutionBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
