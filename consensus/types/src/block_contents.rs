use crate::{
    AbstractExecPayload, BeaconBlock, BeaconBlockAndBlobSidecars, BlobSidecars, EthSpec, ForkName,
    ForkVersionDeserialize,
};
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};

/// A wrapper over a [`BeaconBlock`] or a [`BeaconBlockAndBlobSidecars`].
#[derive(Clone, Debug, Derivative, Serialize, Deserialize)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(untagged)]
#[serde(bound = "T: EthSpec")]
pub enum BlockContents<T: EthSpec, Payload: AbstractExecPayload<T>> {
    BlockAndBlobSidecars(BeaconBlockAndBlobSidecars<T, Payload>),
    Block(BeaconBlock<T, Payload>),
}

impl<T: EthSpec, Payload: AbstractExecPayload<T>> BlockContents<T, Payload> {
    pub fn block(&self) -> &BeaconBlock<T, Payload> {
        match self {
            BlockContents::BlockAndBlobSidecars(block_and_sidecars) => &block_and_sidecars.block,
            BlockContents::Block(block) => block,
        }
    }

    pub fn deconstruct(self) -> (BeaconBlock<T, Payload>, Option<BlobSidecars<T>>) {
        match self {
            BlockContents::BlockAndBlobSidecars(block_and_sidecars) => (
                block_and_sidecars.block,
                Some(block_and_sidecars.blob_sidecars),
            ),
            BlockContents::Block(block) => (block, None),
        }
    }
}

impl<T: EthSpec, Payload: AbstractExecPayload<T>> ForkVersionDeserialize
    for BlockContents<T, Payload>
{
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Base | ForkName::Altair | ForkName::Merge | ForkName::Capella => {
                Ok(BlockContents::Block(BeaconBlock::deserialize_by_fork::<
                    'de,
                    D,
                >(value, fork_name)?))
            }
            ForkName::Eip4844 => Ok(BlockContents::BlockAndBlobSidecars(
                BeaconBlockAndBlobSidecars::deserialize_by_fork::<'de, D>(value, fork_name)?,
            )),
        }
    }
}
