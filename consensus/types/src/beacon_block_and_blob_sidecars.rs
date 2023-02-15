use crate::{
    AbstractExecPayload, BeaconBlock, BlobSidecars, EthSpec, ForkName, ForkVersionDeserialize,
};
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::Encode;
use tree_hash_derive::TreeHash;

#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(bound = "T: EthSpec, Payload: AbstractExecPayload<T>")]
pub struct BeaconBlockAndBlobSidecars<T: EthSpec, Payload: AbstractExecPayload<T>> {
    pub block: BeaconBlock<T, Payload>,
    pub blob_sidecars: BlobSidecars<T>,
}

impl<T: EthSpec, Payload: AbstractExecPayload<T>> ForkVersionDeserialize
    for BeaconBlockAndBlobSidecars<T, Payload>
{
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(bound = "T: EthSpec")]
        struct Helper<T: EthSpec> {
            block: serde_json::Value,
            blob_sidecars: BlobSidecars<T>,
        }
        let helper: Helper<T> = serde_json::from_value(value).map_err(serde::de::Error::custom)?;

        Ok(Self {
            block: BeaconBlock::deserialize_by_fork::<'de, D>(helper.block, fork_name)?,
            blob_sidecars: helper.blob_sidecars,
        })
    }
}
