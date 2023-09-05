use crate::test_utils::TestRandom;
use crate::{Blob, ChainSpec, Domain, EthSpec, Fork, Hash256, SignedBlobSidecar, SignedRoot, Slot};
use bls::SecretKey;
use derivative::Derivative;
use kzg::{Kzg, KzgCommitment, KzgPreset, KzgProof};
use rand::Rng;
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
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
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub blob: Blob<T>,
    pub kzg_commitment: KzgCommitment,
    pub kzg_proof: KzgProof,
}

impl<E: EthSpec> From<Arc<BlobSidecar<E>>> for BlindedBlobSidecar {
    fn from(blob_sidecar: Arc<BlobSidecar<E>>) -> Self {
        BlindedBlobSidecar {
            block_root: blob_sidecar.block_root,
            index: blob_sidecar.index,
            slot: blob_sidecar.slot,
            block_parent_root: blob_sidecar.block_parent_root,
            proposer_index: blob_sidecar.proposer_index,
            blob_root: blob_sidecar.blob.tree_hash_root(),
            kzg_commitment: blob_sidecar.kzg_commitment,
            kzg_proof: blob_sidecar.kzg_proof,
        }
    }
}

impl<E: EthSpec> From<BlobSidecar<E>> for BlindedBlobSidecar {
    fn from(blob_sidecar: BlobSidecar<E>) -> Self {
        BlindedBlobSidecar {
            block_root: blob_sidecar.block_root,
            index: blob_sidecar.index,
            slot: blob_sidecar.slot,
            block_parent_root: blob_sidecar.block_parent_root,
            proposer_index: blob_sidecar.proposer_index,
            blob_root: blob_sidecar.blob.tree_hash_root(),
            kzg_commitment: blob_sidecar.kzg_commitment,
            kzg_proof: blob_sidecar.kzg_proof,
        }
    }
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

impl<T: EthSpec> SignedRoot for BlobSidecar<T> {}

impl<T: EthSpec> BlobSidecar<T> {
    pub fn id(&self) -> BlobIdentifier {
        BlobIdentifier {
            block_root: self.block_root,
            index: self.index,
        }
    }

    pub fn empty() -> Self {
        Self {
            block_root: Hash256::zero(),
            index: 0,
            slot: Slot::new(0),
            block_parent_root: Hash256::zero(),
            proposer_index: 0,
            blob: Blob::<T>::default(),
            kzg_commitment: KzgCommitment::empty_for_testing(),
            kzg_proof: KzgProof::empty(),
        }
    }

    pub fn random_valid<R: Rng>(rng: &mut R, kzg: &Kzg<T::Kzg>) -> Result<Self, String> {
        let mut blob_bytes = vec![0u8; T::Kzg::BYTES_PER_BLOB];
        rng.fill_bytes(&mut blob_bytes);
        // Ensure that the blob is canonical by ensuring that
        // each field element contained in the blob is < BLS_MODULUS
        for i in 0..T::Kzg::FIELD_ELEMENTS_PER_BLOB {
            let Some(byte) = blob_bytes.get_mut(
                i.checked_mul(T::Kzg::BYTES_PER_FIELD_ELEMENT)
                    .ok_or("overflow".to_string())?,
            ) else {
                return Err(format!("blob byte index out of bounds: {:?}", i));
            };
            *byte = 0;
        }

        let blob = Blob::<T>::new(blob_bytes)
            .map_err(|e| format!("error constructing random blob: {:?}", e))?;
        let kzg_blob = T::blob_from_bytes(&blob).unwrap();

        let commitment = kzg
            .blob_to_kzg_commitment(kzg_blob.clone())
            .map_err(|e| format!("error computing kzg commitment: {:?}", e))?;

        let proof = kzg
            .compute_blob_kzg_proof(kzg_blob, commitment)
            .map_err(|e| format!("error computing kzg proof: {:?}", e))?;

        Ok(Self {
            blob,
            kzg_commitment: commitment,
            kzg_proof: proof,
            ..Self::empty()
        })
    }

    #[allow(clippy::arithmetic_side_effects)]
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
            _phantom: PhantomData,
        }
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
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Eq, Hash)]
pub struct BlindedBlobSidecar {
    pub block_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    pub slot: Slot,
    pub block_parent_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub blob_root: Hash256,
    pub kzg_commitment: KzgCommitment,
    pub kzg_proof: KzgProof,
}

impl SignedRoot for BlindedBlobSidecar {}

pub type SidecarList<T, Sidecar> = VariableList<Arc<Sidecar>, <T as EthSpec>::MaxBlobsPerBlock>;
pub type BlobSidecarList<T> = SidecarList<T, BlobSidecar<T>>;
pub type BlindedBlobSidecarList<T> = SidecarList<T, BlindedBlobSidecar>;

pub type FixedBlobSidecarList<T> =
    FixedVector<Option<Arc<BlobSidecar<T>>>, <T as EthSpec>::MaxBlobsPerBlock>;

pub type BlobsList<T> = VariableList<Blob<T>, <T as EthSpec>::MaxBlobCommitmentsPerBlock>;
pub type BlobRootsList<T> = VariableList<Hash256, <T as EthSpec>::MaxBlobCommitmentsPerBlock>;
