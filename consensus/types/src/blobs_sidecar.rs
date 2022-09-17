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
    beacon_block_root: Hash256,
    beacon_block_slot: Slot,
    blobs: VariableList<Blob<T>, T::MaxBlobsPerBlock>,
    kzg_aggregate_proof: KzgProof,
}