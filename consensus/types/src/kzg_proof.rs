use crate::test_utils::{RngCore, TestRandom};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use ssz_derive::{Decode, Encode};
use std::fmt;
use tree_hash::{PackedEncoding, TreeHash};

const KZG_PROOF_BYTES_LEN: usize = 48;

#[derive(
    Debug,
    PartialEq,
    Hash,
    Clone,
    Copy,
    Encode,
    Decode,
    Serialize,
    Deserialize,
    arbitrary::Arbitrary,
)]
#[serde(transparent)]
#[ssz(struct_behaviour = "transparent")]
pub struct KzgProof(#[serde(with = "BigArray")] pub [u8; KZG_PROOF_BYTES_LEN]);

impl fmt::Display for KzgProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", eth2_serde_utils::hex::encode(self.0))
    }
}

impl Default for KzgProof {
    fn default() -> Self {
        KzgProof([0; 48])
    }
}

impl From<[u8; KZG_PROOF_BYTES_LEN]> for KzgProof {
    fn from(bytes: [u8; KZG_PROOF_BYTES_LEN]) -> Self {
        Self(bytes)
    }
}

impl Into<[u8; KZG_PROOF_BYTES_LEN]> for KzgProof {
    fn into(self) -> [u8; KZG_PROOF_BYTES_LEN] {
        self.0
    }
}

impl TreeHash for KzgProof {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <[u8; KZG_PROOF_BYTES_LEN]>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <[u8; KZG_PROOF_BYTES_LEN]>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl TestRandom for KzgProof {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut bytes = [0; KZG_PROOF_BYTES_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}
