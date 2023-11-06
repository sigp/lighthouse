use crate::beacon_block_body::KzgCommitments;
use crate::test_utils::TestRandom;
use crate::{
    AbstractExecPayload, BlindedBlobSidecar, BlindedBlobSidecarList, BlobRootsList, BlobSidecar,
    BlobSidecarList, BlobsList, EthSpec, SidecarList, SignedBeaconBlock, Slot,
};
use kzg::KzgProof;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_types::VariableList;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;
use tree_hash::TreeHash;

pub trait Sidecar<E: EthSpec>:
    serde::Serialize
    + Clone
    + DeserializeOwned
    + Encode
    + Decode
    + Hash
    + TreeHash
    + TestRandom
    + Debug
    + Sync
    + Send
    + for<'a> arbitrary::Arbitrary<'a>
{
    type BlobItems: BlobItems<E>;

    fn slot(&self) -> Slot;

    fn build_sidecar<Payload: AbstractExecPayload<E>>(
        blob_items: Self::BlobItems,
        block: &SignedBeaconBlock<E, Payload>,
        expected_kzg_commitments: &KzgCommitments<E>,
        kzg_proofs: Vec<KzgProof>,
    ) -> Result<SidecarList<E, Self>, String>;
}

pub trait BlobItems<T: EthSpec>:
    Sync + Send + Sized + Debug + Clone + Encode + Decode + Serialize + for<'a> Deserialize<'a>
{
    fn try_from_blob_roots(roots: BlobRootsList<T>) -> Result<Self, String>;
    fn try_from_blobs(blobs: BlobsList<T>) -> Result<Self, String>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn blobs(&self) -> Option<&BlobsList<T>>;
}

impl<T: EthSpec> BlobItems<T> for BlobsList<T> {
    fn try_from_blob_roots(_roots: BlobRootsList<T>) -> Result<Self, String> {
        Err("Unexpected conversion from blob roots to blobs".to_string())
    }

    fn try_from_blobs(blobs: BlobsList<T>) -> Result<Self, String> {
        Ok(blobs)
    }

    fn len(&self) -> usize {
        VariableList::len(self)
    }

    fn is_empty(&self) -> bool {
        VariableList::is_empty(self)
    }

    fn blobs(&self) -> Option<&BlobsList<T>> {
        Some(self)
    }
}

impl<T: EthSpec> BlobItems<T> for BlobRootsList<T> {
    fn try_from_blob_roots(roots: BlobRootsList<T>) -> Result<Self, String> {
        Ok(roots)
    }

    fn try_from_blobs(blobs: BlobsList<T>) -> Result<Self, String> {
        VariableList::new(
            blobs
                .into_iter()
                .map(|blob| blob.tree_hash_root())
                .collect(),
        )
        .map_err(|e| format!("{e:?}"))
    }

    fn len(&self) -> usize {
        VariableList::len(self)
    }

    fn is_empty(&self) -> bool {
        VariableList::is_empty(self)
    }

    fn blobs(&self) -> Option<&BlobsList<T>> {
        None
    }
}

impl<E: EthSpec> Sidecar<E> for BlobSidecar<E> {
    type BlobItems = BlobsList<E>;

    fn slot(&self) -> Slot {
        self.signed_block_header.message.slot
    }

    fn build_sidecar<Payload: AbstractExecPayload<E>>(
        blobs: BlobsList<E>,
        block: &SignedBeaconBlock<E, Payload>,
        expected_kzg_commitments: &KzgCommitments<E>,
        kzg_proofs: Vec<KzgProof>,
    ) -> Result<SidecarList<E, Self>, String> {
        let blob_sidecars = BlobSidecarList::from(
            blobs
                .into_iter()
                .enumerate()
                .map(|(blob_index, blob)| {
                    let kzg_commitment = expected_kzg_commitments
                        .get(blob_index)
                        .ok_or("KZG commitment should exist for blob")?;

                    let kzg_proof = kzg_proofs
                        .get(blob_index)
                        .ok_or("KZG proof should exist for blob")?;

                    Ok(Arc::new(BlobSidecar {
                        index: blob_index as u64,
                        blob,
                        kzg_commitment: *kzg_commitment,
                        kzg_proof: *kzg_proof,
                        signed_block_header: block.signed_block_header(),
                        kzg_commitment_inclusion_proof: block
                            .kzg_commitment_merkle_proof(blob_index)
                            .ok_or_else(|| "KzgCommitment inclusion proof not available")?,
                    }))
                })
                .collect::<Result<Vec<_>, String>>()?,
        );

        Ok(blob_sidecars)
    }
}

impl<E: EthSpec> Sidecar<E> for BlindedBlobSidecar<E> {
    type BlobItems = BlobRootsList<E>;

    fn slot(&self) -> Slot {
        self.signed_block_header.message.slot
    }

    fn build_sidecar<Payload: AbstractExecPayload<E>>(
        blob_roots: BlobRootsList<E>,
        block: &SignedBeaconBlock<E, Payload>,
        expected_kzg_commitments: &KzgCommitments<E>,
        kzg_proofs: Vec<KzgProof>,
    ) -> Result<SidecarList<E, BlindedBlobSidecar<E>>, String> {
        let blob_sidecars = BlindedBlobSidecarList::<E>::from(
            blob_roots
                .into_iter()
                .enumerate()
                .map(|(blob_index, blob_root)| {
                    let kzg_commitment = expected_kzg_commitments
                        .get(blob_index)
                        .ok_or("KZG commitment should exist for blob")?;

                    let kzg_proof = kzg_proofs.get(blob_index).ok_or(format!(
                        "Missing KZG proof for slot {} blob index: {}",
                        block.slot(),
                        blob_index
                    ))?;

                    Ok(Arc::new(BlindedBlobSidecar {
                        index: blob_index as u64,
                        blob_root,
                        kzg_commitment: *kzg_commitment,
                        kzg_proof: *kzg_proof,
                        signed_block_header: block.signed_block_header(),
                        kzg_commitment_inclusion_proof: block
                            .kzg_commitment_merkle_proof(blob_index)
                            .ok_or_else(|| "KzgCommitment inclusion proof not available")?,
                    }))
                })
                .collect::<Result<Vec<_>, String>>()?,
        );

        Ok(blob_sidecars)
    }
}
