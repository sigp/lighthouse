use crate::{BlobsSidecar, EthSpec};
use bls::Signature;
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, PartialEq)]
#[serde(bound = "T: EthSpec")]
pub struct SignedBlobsSidecar<T: EthSpec> {
    pub message: BlobsSidecar<T>,
    pub signature: Signature,
}

impl<T: EthSpec> SignedBlobsSidecar<T> {
    pub fn from_blob(blob: BlobsSidecar<T>, signature: Signature) -> Self {
        Self {
            message: blob,
            signature,
        }
    }
}
