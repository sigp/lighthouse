use ssz_types::VariableList;
use crate::{EthSpec, Hash256, Slot};
use crate::blob::Blob;
use crate::kzg_proof::KzgProof;
use serde::{Serialize, Deserialize};
use ssz_derive::{Encode, Decode};
use tree_hash_derive::TreeHash;
use derivative::Derivative;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, Derivative)]
pub struct BlobsSidecar<T: EthSpec> {
    pub beacon_block_root: Hash256,
    pub beacon_block_slot: Slot,
    pub blobs: VariableList<Blob<T>, T::MaxBlobsPerBlock>,
    pub kzg_aggregate_proof: KzgProof,
}