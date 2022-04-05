use crate::{Blob, BlobsSidecar, EthSpec, Hash256, Slot};
use bls::Signature;
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, PartialEq)]
pub struct SignedBlobsSidecar<E: EthSpec> {
    pub message: BlobsSidecar<E>,
    pub signature: Signature,
}
