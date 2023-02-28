use crate::test_utils::TestRandom;
use crate::*;
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::fmt;
use std::fmt::{Display, Formatter};
use tree_hash::{PackedEncoding, TreeHash};

#[derive(
    Derivative, Debug, Clone, Encode, Decode, Serialize, Deserialize, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Eq, Hash)]
#[ssz(struct_behaviour = "transparent")]
pub struct KzgCommitment(#[serde(with = "BigArray")] pub [u8; 48]);

impl Display for KzgCommitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", eth2_serde_utils::hex::encode(self.0))
    }
}

impl TreeHash for KzgCommitment {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <[u8; 48] as TreeHash>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <[u8; 48] as TreeHash>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl TestRandom for KzgCommitment {
    fn random_for_test(rng: &mut impl rand::RngCore) -> Self {
        KzgCommitment(<[u8; 48] as TestRandom>::random_for_test(rng))
    }
}
