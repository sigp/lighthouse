use crate::{AbstractExecPayload, EthSpec, FullPayload, SignedBeaconBlock, SignedBlobSidecar};
use crate::signed_block_and_blobs::SignedBeaconBlockAndBlobSidecars;
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz_types::VariableList;

/// A wrapper over a [`SignedBeaconBlock`] or a [`SignedBeaconBlockAndBlobSidecars`].
#[derive(Clone, Debug, Derivative, Serialize, Deserialize)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(untagged)]
#[serde(bound = "T: EthSpec")]
pub enum SignedBlockContents<T: EthSpec, Payload: AbstractExecPayload<T> = FullPayload<T>> {
    BlockAndBlobSidecars(SignedBeaconBlockAndBlobSidecars<T, Payload>),
    Block(SignedBeaconBlock<T, Payload>),
}

impl<T: EthSpec, Payload: AbstractExecPayload<T>> SignedBlockContents<T, Payload> {
    pub fn signed_block(&self) -> &SignedBeaconBlock<T, Payload> {
        match self {
            SignedBlockContents::BlockAndBlobSidecars(block_and_sidecars) => &block_and_sidecars.signed_block,
            SignedBlockContents::Block(block) => block,
        }
    }

    pub fn deconstruct(self) -> (SignedBeaconBlock<T, Payload>, Option<VariableList<SignedBlobSidecar<T>, <T as EthSpec>::MaxBlobsPerBlock>>) {
        match self {
            SignedBlockContents::BlockAndBlobSidecars(block_and_sidecars) => (
                block_and_sidecars.signed_block,
                Some(block_and_sidecars.signed_blob_sidecars),
            ),
            SignedBlockContents::Block(block) => (block, None),
        }
    }
}

impl<T: EthSpec, Payload: AbstractExecPayload<T>> From<SignedBeaconBlock<T, Payload>> for SignedBlockContents<T, Payload> {
    fn from(block: SignedBeaconBlock<T, Payload>) -> Self {
        SignedBlockContents::Block(block)
    }
}