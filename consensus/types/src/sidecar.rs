use crate::beacon_block_body::KzgCommitments;
use crate::test_utils::TestRandom;
use crate::{
    AbstractExecPayload, BeaconBlock, BlindedBlobSidecar, BlindedBlobSidecarList, BlobRootsList,
    BlobSidecar, BlobSidecarList, BlobsList, EthSpec, SidecarList, SignedRoot, Slot,
};
use kzg::KzgProof;
use serde::de::DeserializeOwned;
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
    + SignedRoot
    + Sync
    + Send
    + for<'a> arbitrary::Arbitrary<'a>
{
    type BlobItems: BlobItems<E>;
    fn slot(&self) -> Slot;
    fn build_sidecar<Payload: AbstractExecPayload<E>>(
        blob_items: Self::BlobItems,
        block: &BeaconBlock<E, Payload>,
        expected_kzg_commitments: &KzgCommitments<E>,
        kzg_proofs: Vec<KzgProof>,
    ) -> Result<SidecarList<E, Self>, String>;
}

pub trait BlobItems<T: EthSpec>: Sync + Send + Sized {
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

    fn try_from_blobs(_blobs: BlobsList<T>) -> Result<Self, String> {
        // It is possible to convert from blobs to blob roots, however this should be done using
        // `From` or `Into` instead of this generic implementation; this function implementation
        // should be unreachable, and attempt to use this indicates a bug somewhere.
        Err("Unexpected conversion from blob to blob roots".to_string())
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
        self.slot
    }

    fn build_sidecar<Payload: AbstractExecPayload<E>>(
        blobs: BlobsList<E>,
        block: &BeaconBlock<E, Payload>,
        expected_kzg_commitments: &KzgCommitments<E>,
        kzg_proofs: Vec<KzgProof>,
    ) -> Result<SidecarList<E, Self>, String> {
        let beacon_block_root = block.canonical_root();
        let slot = block.slot();
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
                        block_root: beacon_block_root,
                        index: blob_index as u64,
                        slot,
                        block_parent_root: block.parent_root(),
                        proposer_index: block.proposer_index(),
                        blob,
                        kzg_commitment: *kzg_commitment,
                        kzg_proof: *kzg_proof,
                    }))
                })
                .collect::<Result<Vec<_>, String>>()?,
        );

        Ok(blob_sidecars)
    }
}

impl<E: EthSpec> Sidecar<E> for BlindedBlobSidecar {
    type BlobItems = BlobRootsList<E>;

    fn slot(&self) -> Slot {
        self.slot
    }

    fn build_sidecar<Payload: AbstractExecPayload<E>>(
        blob_roots: BlobRootsList<E>,
        block: &BeaconBlock<E, Payload>,
        expected_kzg_commitments: &KzgCommitments<E>,
        kzg_proofs: Vec<KzgProof>,
    ) -> Result<SidecarList<E, BlindedBlobSidecar>, String> {
        let beacon_block_root = block.canonical_root();
        let slot = block.slot();

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
                        slot, blob_index
                    ))?;

                    Ok(Arc::new(BlindedBlobSidecar {
                        block_root: beacon_block_root,
                        index: blob_index as u64,
                        slot,
                        block_parent_root: block.parent_root(),
                        proposer_index: block.proposer_index(),
                        blob_root,
                        kzg_commitment: *kzg_commitment,
                        kzg_proof: *kzg_proof,
                    }))
                })
                .collect::<Result<Vec<_>, String>>()?,
        );

        Ok(blob_sidecars)
    }
}
