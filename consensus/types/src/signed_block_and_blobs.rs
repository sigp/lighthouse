use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
use crate::{BlobsSidecar, EthSpec, SignedBeaconBlock};

#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, PartialEq)]
#[serde(bound = "T: EthSpec")]
pub struct SignedBeaconBlockAndBlobsSidecar<T: EthSpec> {
    pub beacon_block: SignedBeaconBlock<T>,
    pub blobs_sidecar: BlobsSidecar<T>,
}

impl<T: EthSpec> SignedBeaconBlockAndBlobsSidecar<T> {
    /// SSZ decode with fork variant determined by slot.
    pub fn from_ssz_bytes(bytes: &[u8], spec: &ChainSpec) -> Result<Self, ssz::DecodeError> {
        SignedBeaconBlock::from_ssz_bytes(bytes, spec)
    }
}