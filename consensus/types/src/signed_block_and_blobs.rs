use std::sync::Arc;
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, DecodeError};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
use crate::{BlobsSidecar, EthSpec, SignedBeaconBlock, SignedBeaconBlockEip4844};

#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, PartialEq)]
#[serde(bound = "T: EthSpec")]
pub struct SignedBeaconBlockAndBlobsSidecar<T: EthSpec> {
    pub beacon_block: SignedBeaconBlock<T>,
    pub blobs_sidecar: BlobsSidecar<T>,
}

impl <T: EthSpec>Decode for SignedBeaconBlockAndBlobsSidecar<T> {
    fn is_ssz_fixed_len() -> bool {
        todo!()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        todo!()
    }
}

pub enum BlockMaybeBlobs<T: EthSpec> {
    Block(Arc<SignedBeaconBlock<T>>),
    BlockAndBlobs(Arc<SignedBeaconBlockAndBlobsSidecar<T>>),
}

impl <T: EthSpec> BlockMaybeBlobs<T> {
    pub fn blobs(&self) -> Option<&BlobsSidecar<T>>{
        match self {
            Self::Block(_) => None,
            Self::BlockAndBlobs(block_and_blobs) => Some(&block_and_blobs.blobs_sidecar)
        }
    }
}