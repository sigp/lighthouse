use crate::{AbstractExecPayload, BeaconBlock, BlindedBlobSidecar, EthSpec};
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::Encode;
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(bound = "T: EthSpec, Payload: AbstractExecPayload<T>")]
pub struct BeaconBlockAndBlindedBlobSidecars<T: EthSpec, Payload: AbstractExecPayload<T>> {
    pub block: BeaconBlock<T, Payload>,
    pub blinded_blob_sidecars: VariableList<BlindedBlobSidecar, T::MaxBlobsPerBlock>,
}

/// A wrapper over a [`BeaconBlock`] or a [`BeaconBlockAndBlindedBlobSidecars`].
#[derive(Clone, Debug, Derivative, Serialize, Deserialize)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(untagged)]
#[serde(bound = "T: EthSpec")]
pub enum BlockContents<T: EthSpec, Payload: AbstractExecPayload<T>> {
    BlockAndBlobSidecars(BeaconBlockAndBlindedBlobSidecars<T, Payload>),
    Block(BeaconBlock<T, Payload>),
}

type BlindedBlobSidecars<N> = VariableList<BlindedBlobSidecar, N>;

impl<T: EthSpec, Payload: AbstractExecPayload<T>> BlockContents<T, Payload> {
    pub fn block(&self) -> &BeaconBlock<T, Payload> {
        match self {
            BlockContents::BlockAndBlobSidecars(block_and_sidecars) => &block_and_sidecars.block,
            BlockContents::Block(block) => block,
        }
    }

    pub fn deconstruct(
        self,
    ) -> (
        BeaconBlock<T, Payload>,
        Option<BlindedBlobSidecars<T::MaxBlobsPerBlock>>,
    ) {
        match self {
            BlockContents::BlockAndBlobSidecars(block_and_sidecars) => (
                block_and_sidecars.block,
                Some(block_and_sidecars.blinded_blob_sidecars),
            ),
            BlockContents::Block(block) => (block, None),
        }
    }
}

impl<T: EthSpec, Payload: AbstractExecPayload<T>> From<BlockContents<T, Payload>>
    for BeaconBlock<T, Payload>
{
    fn from(block_contents: BlockContents<T, Payload>) -> Self {
        match block_contents {
            BlockContents::BlockAndBlobSidecars(block_and_sidecars) => block_and_sidecars.block,
            BlockContents::Block(block) => block,
        }
    }
}
