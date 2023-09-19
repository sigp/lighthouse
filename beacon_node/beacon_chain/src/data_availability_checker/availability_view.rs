use crate::blob_verification::KzgVerifiedBlob;
use crate::data_availability_checker::overflow_lru_cache::PendingComponents;
use crate::data_availability_checker::ProcessingInfo;
use crate::AvailabilityPendingExecutedBlock;
use kzg::KzgCommitment;
use ssz_types::FixedVector;
use types::beacon_block_body::{ KzgCommitments};
use types::EthSpec;

/// This trait is meant to ensure we maintain the following invariants across caches used in
/// availability checking:
///
/// 1. Never clobber blobs when adding new blobs.
/// 2. When adding a block, evict all blobs whose KZG commitments do not match the block's.
pub trait AvailabilityView<E: EthSpec> {
    type BlockType;
    type BlobType: Clone;

    fn block_exists(&self) -> bool;
    fn blob_exists(&self, blob_index: u64) -> bool;
    fn num_expected_blobs(&self) -> usize;
    fn num_received_blobs(&self) -> usize;
    fn insert_block(&mut self, block: Self::BlockType);
    fn insert_blob_at_index(&mut self, blob_index: u64, blob: &Self::BlobType);
    fn blob_to_commitment(blob: &Self::BlobType) -> KzgCommitment;
    fn get_cached_blob_commitments_mut(
        &mut self,
    ) -> &mut FixedVector<Option<Self::BlobType>, E::MaxBlobsPerBlock>;
    fn get_block_commitment_at_index(&self, blob_index: u64) -> Option<KzgCommitment>;
    /// validate the index
    /// only insert if:
    /// 1. the blob entry is empty and there is no block
    /// 2. the block exists and the commitment matches
    fn merge_blobs(&mut self, blobs: FixedVector<Option<Self::BlobType>, E::MaxBlobsPerBlock>) {
        for (index, blob) in blobs.into_iter().enumerate() {
            let Some(blob) = blob else { continue };
            let commitment = Self::blob_to_commitment(blob);

            let index = index as u64;

            if let Some(block_commitment) = self.get_block_commitment_at_index(index) {
                if block_commitment == commitment {
                    self.insert_blob_at_index(index, blob)
                }
            } else {
                if !self.blob_exists(index) {
                    self.insert_blob_at_index(index, blob)
                }
            }
        }
    }
    fn merge_block(&mut self, block: Self::BlockType) {
        self.insert_block(block);
        let cached = self.get_cached_blob_commitments_mut();
        let mut reinsert = FixedVector::default();
        for (index, cached_blob) in cached.iter_mut().enumerate() {
            // Take the existing blobs and re-insert them.
            reinsert
                .get_mut(index)
                .map(|blob| *blob = cached_blob.take());
        }

        self.merge_blobs(reinsert)
    }
    fn is_available(&self) -> bool {
        self.block_exists() && self.num_expected_blobs() == self.num_received_blobs()
    }
}

impl<E: EthSpec> AvailabilityView<E> for ProcessingInfo<E> {
    type BlockType = KzgCommitments<E>;
    type BlobType = KzgCommitment;

    fn block_exists(&self) -> bool {
        self.kzg_commitments.is_some()
    }

    fn blob_exists(&self, blob_index: u64) -> bool {
        self.processing_blobs
            .get(blob_index as usize)
            .map(|b| b.is_some())
            .unwrap_or(false)
    }

    fn num_expected_blobs(&self) -> usize {
        self.kzg_commitments.as_ref().map_or(0, |c| c.len())
    }

    fn num_received_blobs(&self) -> usize {
        self.processing_blobs.iter().flatten().count()
    }

    fn insert_block(&mut self, block: Self::BlockType) {
        let _ = self.kzg_commitments.insert(block);
    }

    fn insert_blob_at_index(&mut self, blob_index: u64, blob: &Self::BlobType) {
        if let Some(b) = self.processing_blobs.get_mut(blob_index as usize) {
            *b = Some(blob.clone());
        }
    }

    fn blob_to_commitment(blob: &Self::BlobType) -> KzgCommitment {
        *blob
    }

    fn get_cached_blob_commitments_mut(
        &mut self,
    ) -> &mut FixedVector<Option<Self::BlobType>, E::MaxBlobsPerBlock> {
        &mut self.processing_blobs
    }

    fn get_block_commitment_at_index(&self, blob_index: u64) -> Option<KzgCommitment> {
        self.processing_blobs
            .get(blob_index as usize)
            .and_then(|b| b.clone())
    }
}

impl<E: EthSpec> AvailabilityView<E> for PendingComponents<E> {
    type BlockType = AvailabilityPendingExecutedBlock<E>;
    type BlobType = KzgVerifiedBlob<E>;

    fn block_exists(&self) -> bool {
        self.executed_block.is_some()
    }

    fn blob_exists(&self, blob_index: u64) -> bool {
        self.verified_blobs
            .get(blob_index as usize)
            .map(|b| b.is_some())
            .unwrap_or(false)
    }

    fn num_expected_blobs(&self) -> usize {
        self.executed_block
            .as_ref()
            .map_or(0, |b| b.num_blobs_expected())
    }

    fn num_received_blobs(&self) -> usize {
        self.verified_blobs.iter().flatten().count()
    }

    fn insert_block(&mut self, block: Self::BlockType) {
        self.executed_block = Some(block);
    }

    fn insert_blob_at_index(&mut self, blob_index: u64, blob: &Self::BlobType) {
        if let Some(b) = self.verified_blobs.get_mut(blob_index as usize) {
            *b = Some(blob.clone());
        }
    }

    fn blob_to_commitment(blob: &Self::BlobType) -> KzgCommitment {
        blob.as_blob().kzg_commitment
    }

    fn get_cached_blob_commitments_mut(
        &mut self,
    ) -> &mut FixedVector<Option<Self::BlobType>, E::MaxBlobsPerBlock> {
        &mut self.verified_blobs
    }

    fn get_block_commitment_at_index(&self, blob_index: u64) -> Option<KzgCommitment> {
        self.executed_block.as_ref().and_then(|b| {
            b.block
                .message()
                .body()
                .blob_kzg_commitments()
                .ok()
                .and_then(|c| c.get(blob_index as usize).cloned())
        })
    }
}
