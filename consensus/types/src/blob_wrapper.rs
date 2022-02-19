use crate::{Blob, EthSpec, Hash256, SignedBeaconBlock, Slot};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::Encode;
use ssz_types::VariableList;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash)]
pub struct BlobWrapper<E: EthSpec> {
    pub beacon_block_root: Hash256,
    pub beacon_block_slot: Slot,
    pub blobs: VariableList<Blob<E::ChunksPerBlob>, E::MaxObjectListSize>,
}
