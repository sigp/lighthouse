use crate::blob_verification::KzgVerifiedBlob;
use crate::data_availability_checker::overflow_lru_cache::PendingComponents;
use crate::data_availability_checker::ProcessingInfo;
use crate::AvailabilityPendingExecutedBlock;
use kzg::KzgCommitment;
use ssz_types::FixedVector;
use types::beacon_block_body::KzgCommitments;
use types::EthSpec;

/// Defines an interface for managing data availability with two key invariants:
/// 1. Blobs won't be clobbered if we've yet to see the corresponding block.
/// 2. On block insertion, any non-matching blob commitments are evicted.
///
/// Types implementing this trait can be used for validating and managing availability
/// of blocks and blobs in a cache-like data structure.
pub trait AvailabilityView<E: EthSpec> {
    /// The type representing a block in the implementation.
    type BlockType;

    /// The type representing a blob in the implementation. Must implement `Clone`.
    type BlobType: Clone;

    /// Checks if a block exists in the cache.
    ///
    /// Returns:
    /// - `true` if a block exists.
    /// - `false` otherwise.
    fn block_exists(&self) -> bool;

    /// Checks if a blob exists at the given index in the cache.
    ///
    /// Returns:
    /// - `true` if a blob exists at the given index.
    /// - `false` otherwise.
    fn blob_exists(&self, blob_index: u64) -> bool;

    /// Returns the number of blobs that are expected to be present. Returns 0 if we don't have a
    /// block.
    ///
    /// This corresponds to the number of commitments that are present in a block.
    fn num_expected_blobs(&self) -> usize;

    /// Returns the number of blobs that have been received and are stored in the cache.
    fn num_received_blobs(&self) -> usize;

    /// Inserts a block into the cache.
    fn insert_block(&mut self, block: Self::BlockType);

    /// Inserts a blob at a specific index in the cache.
    ///
    /// Existing blob at the index will be replaced.
    fn insert_blob_at_index(&mut self, blob_index: u64, blob: &Self::BlobType);

    /// Converts a blob to its KZG commitment.
    fn blob_to_commitment(blob: &Self::BlobType) -> KzgCommitment;

    /// Provides mutable access to the underlying blob commitments cache.
    fn get_cached_blob_commitments_mut(
        &mut self,
    ) -> &mut FixedVector<Option<Self::BlobType>, E::MaxBlobsPerBlock>;

    /// Retrieves the KZG commitment of the blob stored at the given index in the block.
    ///
    /// Returns `None` if no blob is present at the index.
    fn get_block_commitment_at_index(&self, blob_index: u64) -> Option<KzgCommitment>;

    /// Merges a given set of blobs into the cache.
    ///
    /// Blobs are only inserted if:
    /// 1. The blob entry at the index is empty and no block exists.
    /// 2. The block exists and its commitment matches the blob's commitment.
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

    /// Inserts a new block and revalidates the existing blobs against it.
    ///
    /// Blobs that don't match the new block's commitments are evicted.
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

    /// Checks if the block and all of its expected blobs are available in the cache.
    ///
    /// Returns `true` if both the block exists and the number of received blobs matches the number
    /// of expected blobs.
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
