use bls::Signature;
use crate::blobs_sidecar::BlobsSidecar;
use crate::EthSpec;
use serde::{Serialize, Deserialize};
use ssz_derive::{Encode, Decode};
use tree_hash_derive::TreeHash;
use derivative::Derivative;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, Derivative)]
pub struct SignedBlobsSidecar<T: EthSpec> {
    pub message: BlobsSidecar<T>,
    pub signature: Signature,
}