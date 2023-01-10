use crate::kzg_proof::KzgProof;
use crate::{Blob, EthSpec, Hash256, SignedRoot, Slot};
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    PartialEq,
    Default,
    arbitrary::Arbitrary,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
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
