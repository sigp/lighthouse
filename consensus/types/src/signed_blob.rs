use crate::sidecar::Sidecar;
use crate::{
    test_utils::TestRandom, BlindedBlobSidecar, Blob, BlobSidecar, ChainSpec, Domain, EthSpec,
    Fork, Hash256, Signature, SignedRoot, SigningData,
};
use bls::PublicKey;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::marker::PhantomData;
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
#[serde(bound = "T: EthSpec, S: Sidecar<T>")]
#[arbitrary(bound = "T: EthSpec, S: Sidecar<T>")]
#[derivative(Hash(bound = "T: EthSpec, S: Sidecar<T>"))]
pub struct SignedSidecar<T: EthSpec, S: Sidecar<T>> {
    pub message: Arc<S>,
    pub signature: Signature,
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[serde(skip)]
    #[arbitrary(default)]
    pub _phantom: PhantomData<T>,
}

impl<T: EthSpec> SignedSidecar<T, BlindedBlobSidecar> {
    pub fn into_full_blob_sidecars(self, blob: Blob<T>) -> SignedSidecar<T, BlobSidecar<T>> {
        let blinded_sidecar = self.message;
        SignedSidecar {
            message: Arc::new(BlobSidecar {
                block_root: blinded_sidecar.block_root,
                index: blinded_sidecar.index,
                slot: blinded_sidecar.slot,
                block_parent_root: blinded_sidecar.block_parent_root,
                proposer_index: blinded_sidecar.proposer_index,
                blob,
                kzg_commitment: blinded_sidecar.kzg_commitment,
                kzg_proof: blinded_sidecar.kzg_proof,
            }),
            signature: self.signature,
            _phantom: PhantomData,
        }
    }
}

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

impl<T: EthSpec> From<SignedBlobSidecar<T>> for SignedBlindedBlobSidecar<T> {
    fn from(signed: SignedBlobSidecar<T>) -> Self {
        SignedBlindedBlobSidecar {
            message: Arc::new(signed.message.into()),
            signature: signed.signature,
            _phantom: PhantomData,
        }
    }
}

pub type SignedBlobSidecar<T> = SignedSidecar<T, BlobSidecar<T>>;
pub type SignedBlindedBlobSidecar<T> = SignedSidecar<T, BlindedBlobSidecar>;

/// List of Signed Sidecars that implements `Sidecar`.
pub type SignedSidecarList<T, Sidecar> =
    VariableList<SignedSidecar<T, Sidecar>, <T as EthSpec>::MaxBlobsPerBlock>;
pub type SignedBlobSidecarList<T> = SignedSidecarList<T, BlobSidecar<T>>;
pub type SignedBlindedBlobSidecarList<T> = SignedSidecarList<T, BlindedBlobSidecar>;
