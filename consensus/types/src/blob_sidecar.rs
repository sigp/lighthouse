use crate::test_utils::TestRandom;
use crate::{Blob, ChainSpec, Domain, EthSpec, Fork, Hash256, SignedBlobSidecar, SignedRoot, Slot};
use bls::SecretKey;
use derivative::Derivative;
use kzg::{KzgCommitment, KzgProof};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Container of the data that identifies an individual blob.
#[derive(
    Serialize, Deserialize, Encode, Decode, TreeHash, Copy, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct BlobIdentifier {
    pub block_root: Hash256,
    pub index: u64,
}

impl PartialOrd for BlobIdentifier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.index.partial_cmp(&other.index)
    }
}

impl Ord for BlobIdentifier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.index.cmp(&other.index)
    }
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    Default,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
#[derivative(PartialEq, Eq, Hash(bound = "T: EthSpec"))]
pub struct BlobSidecar<T: EthSpec> {
    pub block_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    pub slot: Slot,
    pub block_parent_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[serde(with = "serde_kzg_blob")]
    pub blob: Blob,
    pub kzg_commitment: KzgCommitment,
    pub kzg_proof: KzgProof,
    #[serde(skip)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    pub _phantom: std::marker::PhantomData<T>,
}

impl<T: EthSpec> PartialOrd for BlobSidecar<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.index.partial_cmp(&other.index)
    }
}

impl<T: EthSpec> Ord for BlobSidecar<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.index.cmp(&other.index)
    }
}

pub type BlobSidecarList<T> = VariableList<Arc<BlobSidecar<T>>, <T as EthSpec>::MaxBlobsPerBlock>;
pub type FixedBlobSidecarList<T> =
    FixedVector<Option<Arc<BlobSidecar<T>>>, <T as EthSpec>::MaxBlobsPerBlock>;
pub type Blobs<E> = VariableList<Blob, <E as EthSpec>::MaxBlobsPerBlock>;

impl<T: EthSpec> SignedRoot for BlobSidecar<T> {}

impl<T: EthSpec> BlobSidecar<T> {
    pub fn id(&self) -> BlobIdentifier {
        BlobIdentifier {
            block_root: self.block_root,
            index: self.index,
        }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    #[allow(clippy::integer_arithmetic)]
    pub fn max_size() -> usize {
        // Fixed part
        Self::empty().as_ssz_bytes().len()
    }

    // this is mostly not used except for in testing
    pub fn sign(
        self: Arc<Self>,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> SignedBlobSidecar<T> {
        let signing_epoch = self.slot.epoch(T::slots_per_epoch());
        let domain = spec.get_domain(
            signing_epoch,
            Domain::BlobSidecar,
            fork,
            genesis_validators_root,
        );
        let message = self.signing_root(domain);
        let signature = secret_key.sign(message);

        SignedBlobSidecar {
            message: self,
            signature,
        }
    }
}

pub mod serde_kzg_blob {
    use super::*;

    pub fn serialize<S>(blob: &Blob, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&serde_utils::hex::encode(blob))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Blob, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        Blob::from_hex(&s)
            .map_err(|e| format!("invalid hex: {:?}", e))
            .map_err(D::Error::custom)
    }
}
