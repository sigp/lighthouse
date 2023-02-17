use crate::test_utils::TestRandom;
use crate::{Blob, EthSpec, Hash256, SignedRoot, Slot};
use bls::Signature;
use derivative::Derivative;
use kzg::{KzgCommitment, KzgProof};
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    Default,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
pub struct BlobSidecar<T: EthSpec> {
    pub block_root: Hash256,
    // TODO: fix the type, should fit in u8 as well
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub index: u64,
    pub slot: Slot,
    pub block_parent_root: Hash256,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub blob: Blob<T>,
    pub kzg_commitment: KzgCommitment,
    pub kzg_proof: KzgProof,
}

impl<T: EthSpec> SignedRoot for BlobSidecar<T> {}

impl<T: EthSpec> BlobSidecar<T> {
    pub fn empty() -> Self {
        Self::default()
    }

    #[allow(clippy::integer_arithmetic)]
    pub fn max_size() -> usize {
        // Fixed part
        Self::empty().as_ssz_bytes().len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Default, Derivative)]
#[derivative(PartialEq, Hash)]
pub struct BlindedBlobSidecar {
    pub block_root: Hash256,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub index: u64,
    pub slot: Slot,
    pub block_parent_root: Hash256,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub blob_root: Hash256,
    pub kzg_commitment: KzgCommitment,
    pub kzg_proof: KzgProof,
}

impl<T: EthSpec> From<Arc<BlobSidecar<T>>> for BlindedBlobSidecar {
    fn from(value: Arc<BlobSidecar<T>>) -> Self {
        Self {
            block_root: value.block_root,
            index: value.index,
            slot: value.slot,
            block_parent_root: value.block_parent_root,
            proposer_index: value.proposer_index,
            blob_root: value.blob.tree_hash_root(),
            kzg_commitment: value.kzg_commitment.clone(),
            kzg_proof: value.kzg_proof,
        }
    }
}

impl SignedRoot for BlindedBlobSidecar {}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Derivative)]
#[derivative(PartialEq, Hash)]
pub struct SignedBlindedBlobSidecar {
    pub message: BlindedBlobSidecar,
    pub signature: Signature,
}
