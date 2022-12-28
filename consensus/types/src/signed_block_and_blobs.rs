use crate::signed_beacon_block::BlobReconstructionError;
use crate::{BlobsSidecar, EthSpec, Hash256, SignedBeaconBlock, SignedBeaconBlockEip4844, Slot};
use derivative::Derivative;
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

#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
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
#[derive(Clone, Debug, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
pub enum BlockWrapper<T: EthSpec> {
    Block(Arc<SignedBeaconBlock<T>>),
    BlockAndBlob(SignedBeaconBlockAndBlobsSidecar<T>),
}

impl<T: EthSpec> BlockWrapper<T> {
    pub fn slot(&self) -> Slot {
        match self {
            BlockWrapper::Block(block) => block.slot(),
            BlockWrapper::BlockAndBlob(block_sidecar_pair) => {
                block_sidecar_pair.beacon_block.slot()
            }
        }
    }
    pub fn block(&self) -> &SignedBeaconBlock<T> {
        match self {
            BlockWrapper::Block(block) => &block,
            BlockWrapper::BlockAndBlob(block_sidecar_pair) => &block_sidecar_pair.beacon_block,
        }
    }
    pub fn block_cloned(&self) -> Arc<SignedBeaconBlock<T>> {
        match self {
            BlockWrapper::Block(block) => block.clone(),
            BlockWrapper::BlockAndBlob(block_sidecar_pair) => {
                block_sidecar_pair.beacon_block.clone()
            }
        }
    }

    pub fn blobs(
        &self,
        block_root: Option<Hash256>,
    ) -> Result<Option<Arc<BlobsSidecar<T>>>, BlobReconstructionError> {
        match self {
            BlockWrapper::Block(block) => block
                .reconstruct_empty_blobs(block_root)
                .map(|blob_opt| blob_opt.map(Arc::new)),
            BlockWrapper::BlockAndBlob(block_sidecar_pair) => {
                Ok(Some(block_sidecar_pair.blobs_sidecar.clone()))
            }
        }
    }

    pub fn message(&self) -> crate::BeaconBlockRef<T> {
        match self {
            BlockWrapper::Block(block) => block.message(),
            BlockWrapper::BlockAndBlob(block_sidecar_pair) => {
                block_sidecar_pair.beacon_block.message()
            }
        }
    }

    pub fn parent_root(&self) -> Hash256 {
        self.block().parent_root()
    }

    pub fn deconstruct(
        self,
        block_root: Option<Hash256>,
    ) -> (
        Arc<SignedBeaconBlock<T>>,
        Result<Option<Arc<BlobsSidecar<T>>>, BlobReconstructionError>,
    ) {
        match self {
            BlockWrapper::Block(block) => {
                let blobs = block
                    .reconstruct_empty_blobs(block_root)
                    .map(|blob_opt| blob_opt.map(Arc::new));
                (block, blobs)
            }
            BlockWrapper::BlockAndBlob(block_sidecar_pair) => {
                let SignedBeaconBlockAndBlobsSidecar {
                    beacon_block,
                    blobs_sidecar,
                } = block_sidecar_pair;
                (beacon_block, Ok(Some(blobs_sidecar)))
            }
        }
    }
}

impl<T: EthSpec> From<SignedBeaconBlock<T>> for BlockWrapper<T> {
    fn from(block: SignedBeaconBlock<T>) -> Self {
        BlockWrapper::Block(Arc::new(block))
    }
}

impl<T: EthSpec> From<Arc<SignedBeaconBlock<T>>> for BlockWrapper<T> {
    fn from(block: Arc<SignedBeaconBlock<T>>) -> Self {
        BlockWrapper::Block(block)
    }
}
