use crate::{
    test_utils::TestRandom, BlobSidecar, ChainSpec, Domain, EthSpec, Fork, Hash256, Signature,
    SignedRoot, SigningData,
};
use bls::PublicKey;
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TestRandom,
    TreeHash,
    Derivative,
    arbitrary::Arbitrary,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
#[derivative(Hash(bound = "T: EthSpec"))]
pub struct SignedBlobSidecar<T: EthSpec> {
    pub message: Arc<BlobSidecar<T>>,
    pub signature: Signature,
}

pub type SignedBlobSidecarList<T> =
    VariableList<SignedBlobSidecar<T>, <T as EthSpec>::MaxBlobsPerBlock>;

impl<T: EthSpec> SignedBlobSidecar<T> {
    /// Verify `self.signature`.
    ///
    /// If the root of `block.message` is already known it can be passed in via `object_root_opt`.
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
            self.message.slot.epoch(T::slots_per_epoch()),
            Domain::BlobSidecar,
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
