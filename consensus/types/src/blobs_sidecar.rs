use crate::kzg_proof::KzgProof;
use crate::{Blob, EthSpec, Hash256, Slot};
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, PartialEq, Default)]
pub struct BlobsSidecar<E: EthSpec> {
    pub beacon_block_root: Hash256,
    pub beacon_block_slot: Slot,
    pub blobs: VariableList<Blob<E>, E::MaxBlobsPerBlock>,
    pub kzg_aggregate_proof: KzgProof,
}

impl<E: EthSpec> BlobsSidecar<E> {
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn max_size() -> usize {
        // Fixed part
        Self::empty().as_ssz_bytes().len()
            // Max size of variable length `blobs` field
            + (E::max_blobs_per_block() * <Blob<E> as Encode>::ssz_fixed_len())
    }
}
