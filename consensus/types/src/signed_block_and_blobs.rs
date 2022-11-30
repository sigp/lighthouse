use crate::{BlobsSidecar, EthSpec, Hash256, SignedBeaconBlock, SignedBeaconBlockEip4844, Slot};
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
#[derive(Clone, Debug)]
pub enum BlockWrapper<T: EthSpec> {
    Block {
        block: Arc<SignedBeaconBlock<T>>,
    },
    BlockAndBlob {
        block_sidecar_pair: SignedBeaconBlockAndBlobsSidecar<T>,
    },
}

impl<T: EthSpec> BlockWrapper<T> {
    pub fn slot(&self) -> Slot {
        match self {
            BlockWrapper::Block { block } => block.slot(),
            BlockWrapper::BlockAndBlob { block_sidecar_pair } => {
                block_sidecar_pair.beacon_block.slot()
            }
        }
    }
    pub fn block(&self) -> &SignedBeaconBlock<T> {
        match self {
            BlockWrapper::Block { block } => &block,
            BlockWrapper::BlockAndBlob { block_sidecar_pair } => &block_sidecar_pair.beacon_block,
        }
    }
    pub fn block_cloned(&self) -> Arc<SignedBeaconBlock<T>> {
        match self {
            BlockWrapper::Block { block } => block.clone(),
            BlockWrapper::BlockAndBlob { block_sidecar_pair } => {
                block_sidecar_pair.beacon_block.clone()
            }
        }
    }
    pub fn blocks_sidecar(&self) -> Option<Arc<BlobsSidecar<T>>> {
        match self {
            BlockWrapper::Block { block: _ } => None,
            BlockWrapper::BlockAndBlob { block_sidecar_pair } => {
                Some(block_sidecar_pair.blobs_sidecar.clone())
            }
        }
    }

    pub fn parent_root(&self) -> Hash256 {
        self.block().parent_root()
    }

    pub fn deconstruct(self) -> (Arc<SignedBeaconBlock<T>>, Option<Arc<BlobsSidecar<T>>>) {
        match self {
            BlockWrapper::Block { block } => (block, None),
            BlockWrapper::BlockAndBlob { block_sidecar_pair } => {
                let SignedBeaconBlockAndBlobsSidecar {
                    beacon_block,
                    blobs_sidecar,
                } = block_sidecar_pair;
                (beacon_block, Some(blobs_sidecar))
            }
        }
    }
}

// TODO: probably needes to be changed. This is needed because SignedBeaconBlockAndBlobsSidecar
// does not implement Hash
impl<T: EthSpec> std::hash::Hash for BlockWrapper<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            BlockWrapper::Block { block } => block.hash(state),
            BlockWrapper::BlockAndBlob {
                block_sidecar_pair: block_and_blob,
            } => block_and_blob.beacon_block.hash(state),
        }
    }
}

impl<T: EthSpec> From<SignedBeaconBlock<T>> for BlockWrapper<T> {
    fn from(block: SignedBeaconBlock<T>) -> Self {
        BlockWrapper::Block {
            block: Arc::new(block),
        }
    }
}

impl<T: EthSpec> From<Arc<SignedBeaconBlock<T>>> for BlockWrapper<T> {
    fn from(block: Arc<SignedBeaconBlock<T>>) -> Self {
        BlockWrapper::Block { block }
    }
}
