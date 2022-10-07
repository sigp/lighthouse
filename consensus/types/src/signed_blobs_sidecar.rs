use crate::{
    signing_data::SignedRoot, BlobsSidecar, ChainSpec, Domain, EthSpec, Fork, Hash256, PublicKey,
    SigningData,
};
use bls::Signature;
use serde_derive::{Deserialize, Serialize};
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

    /// Verify `self.signature`.
    ///
    /// If the root of `blob_sidecar.message` is already known it can be passed in via `object_root_opt`.
    /// Otherwise, it will be computed locally.
    pub fn verify_signature(
        &self,
        object_root_opt: Option<Hash256>,
        pubkey: &PublicKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> bool {
        let domain = spec.get_domain(
            self.message.beacon_block_slot.epoch(T::slots_per_epoch()),
            Domain::BlobsSideCar,
            fork,
            genesis_validators_root,
        );

        let message = if let Some(object_root) = object_root_opt {
            SigningData {
                object_root,
                domain,
            }
            .tree_hash_root()
        } else {
            self.message.signing_root(domain)
        };

        self.signature.verify(pubkey, message)
    }
}
