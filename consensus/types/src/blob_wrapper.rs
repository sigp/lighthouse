use crate::{Blob, EthSpec, Hash256, SignedBeaconBlock, Slot};
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, PartialEq, Default)]
pub struct BlobWrapper<E: EthSpec> {
    pub beacon_block_root: Hash256,
    pub beacon_block_slot: Slot,
    pub blobs: VariableList<Blob<E::ChunksPerBlob>, E::MaxObjectListSize>,
}

impl<E: EthSpec> BlobWrapper<E> {
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn max_size() -> usize {
        // Fixed part
        Self::empty().as_ssz_bytes().len()
            // Max size of variable length `blobs` field
            + (E::max_object_list_size() * <Blob<E::ChunksPerBlob> as Encode>::ssz_fixed_len())
    }
}
