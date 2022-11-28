use crate::{BlobsSidecar, EthSpec, SignedBeaconBlock, SignedBeaconBlockEip4844};
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, DecodeError};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use tree_hash_derive::TreeHash;

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, PartialEq)]
#[serde(bound = "T: EthSpec")]
pub struct SignedBeaconBlockAndBlobsSidecarDecode<T: EthSpec> {
    pub beacon_block: SignedBeaconBlockEip4844<T>,
    pub blobs_sidecar: BlobsSidecar<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, PartialEq)]
#[serde(bound = "T: EthSpec")]
pub struct SignedBeaconBlockAndBlobsSidecar<T: EthSpec> {
    pub beacon_block: Arc<SignedBeaconBlock<T>>,
    pub blobs_sidecar: Arc<BlobsSidecar<T>>,
}

impl<T: EthSpec> SignedBeaconBlockAndBlobsSidecar<T> {
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let SignedBeaconBlockAndBlobsSidecarDecode {
            beacon_block,
            blobs_sidecar,
        } = SignedBeaconBlockAndBlobsSidecarDecode::from_ssz_bytes(bytes)?;
        Ok(SignedBeaconBlockAndBlobsSidecar {
            beacon_block: Arc::new(SignedBeaconBlock::Eip4844(beacon_block)),
            blobs_sidecar: Arc::new(blobs_sidecar),
        })
    }
}

/// A wrapper over a [`SignedBeaconBlock`] or a [`SignedBeaconBlockAndBlobsSidecar`].
pub enum BlockWrapper<T: EthSpec> {
    Block {
        block: Arc<SignedBeaconBlock<T>>,
    },
    BlockAndBlob {
        block_sidecar_pair: SignedBeaconBlockAndBlobsSidecar<T>,
    },
}

impl<T: EthSpec> BlockWrapper<T> {
    pub fn block(&self) -> &SignedBeaconBlock<T> {
        match self {
            BlockWrapper::Block { block } => &block,
            BlockWrapper::BlockAndBlob { block_sidecar_pair } => &block_sidecar_pair.beacon_block,
        }
    }
}
