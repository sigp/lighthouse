use crate::{
    AbstractExecPayload, BlobsSidecar, EthSpec, SignedBeaconBlock, SignedBeaconBlockEip4844,
    SignedBlobSidecar,
};
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, DecodeError};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::sync::Arc;
use tree_hash_derive::TreeHash;

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, PartialEq)]
#[serde(bound = "T: EthSpec")]
pub struct SignedBeaconBlockAndBlobsSidecarDecode<T: EthSpec> {
    pub beacon_block: SignedBeaconBlockEip4844<T>,
    pub blobs_sidecar: BlobsSidecar<T>,
}

// TODO: will be removed once we decouple blobs in Gossip
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

#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(bound = "T: EthSpec")]
pub struct SignedBeaconBlockAndBlobSidecars<T: EthSpec, Payload: AbstractExecPayload<T>> {
    pub signed_block: SignedBeaconBlock<T, Payload>,
    pub signed_blob_sidecars: VariableList<SignedBlobSidecar<T>, <T as EthSpec>::MaxBlobsPerBlock>,
}
