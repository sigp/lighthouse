use crate::{Blob, EthSpec, Hash256, SignedRoot, Slot};
use kzg::KzgProof;
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, PartialEq, Default)]
#[serde(bound = "T: EthSpec")]
pub struct BlobsSidecar<T: EthSpec> {
    pub beacon_block_root: Hash256,
    pub beacon_block_slot: Slot,
    pub blobs: VariableList<Blob<T>, T::MaxBlobsPerBlock>,
    pub kzg_aggregate_proof: KzgProof,
}

impl<T: EthSpec> SignedRoot for BlobsSidecar<T> {}

impl<T: EthSpec> BlobsSidecar<T> {
    pub fn empty() -> Self {
        Self::default()
    }
    #[allow(clippy::integer_arithmetic)]
    pub fn max_size() -> usize {
        // Fixed part
        Self::empty().as_ssz_bytes().len()
            // Max size of variable length `blobs` field
            + (T::max_blobs_per_block() * <Blob<T> as Encode>::ssz_fixed_len())
    }
}
