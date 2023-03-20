use crate::test_utils::TestRandom;
use crate::{Blob, EthSpec, Hash256, SignedRoot, Slot};
use derivative::Derivative;
use kzg::{KzgCommitment, KzgProof};
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Container of the data that identifies an individual blob.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlobIdentifier {
    pub block_root: Hash256,
    pub index: u64,
}

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

pub type BlobSidecarList<T> = VariableList<BlobSidecar<T>, <T as EthSpec>::MaxBlobsPerBlock>;
//TODO(sean) is there any other way around this? need it arc blobs for caching in multiple places
pub type BlobSidecarArcList<T> =
    VariableList<Arc<BlobSidecar<T>>, <T as EthSpec>::MaxBlobsPerBlock>;
pub type Blobs<T> = VariableList<Blob<T>, <T as EthSpec>::MaxExtraDataBytes>;

impl<T: EthSpec> SignedRoot for BlobSidecar<T> {}

impl<T: EthSpec> BlobSidecar<T> {
    pub fn id(&self) -> BlobIdentifier {
        BlobIdentifier {
            block_root: self.block_root,
            index: self.index,
        }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    #[allow(clippy::integer_arithmetic)]
    pub fn max_size() -> usize {
        // Fixed part
        Self::empty().as_ssz_bytes().len()
    }
}
