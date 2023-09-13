use crate::blob_verification::GossipVerifiedBlob;
use crate::data_availability_checker::overflow_lru_cache::MissingBlobInfo;
use crate::data_availability_checker::{Availability, AvailabilityCheckError};
use crate::GossipVerifiedBlock;
use kzg::KzgCommitment;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use types::beacon_block_body::KzgCommitments;
use types::blob_sidecar::BlobIdentifier;
use types::{BlobSidecar, EthSpec, Hash256, Slot};

/// This cache is used only for gossip and single lookups, to give req/resp a view of what we have
/// and what we require. This cache serves a slightly different purpose than gossip caches. It
/// tracks all unique messages we're currently processing, or have already processed. This should
/// be used in conjunction with the `data_availability_cache` to have a full view of processing
/// statuses.
///
/// Components should be atomically removed when being added to the data availability cache.
///
/// Components should be atomically inserted into the `processed_cache` when removed from the
/// `data_availability_cache` for import (removed as `Available`).
#[derive(Default)]
pub struct ProcessingCache<E: EthSpec> {
    //TODO: Fnv hash map? lru cache?
    processing_cache: HashMap<Hash256, SimplifiedPendingComponents<E>>,
    processed_cache: HashSet<Hash256>,
}

#[derive(Default)]
pub struct SimplifiedPendingComponents<E: EthSpec> {
    /// Blobs required for a block can only be known if we have seen the block. So `Some` here
    /// means we've seen it, a `None` means we haven't. The `kzg_commitments` value is also
    /// necessary to verify the .
    kzg_commitments: Option<KzgCommitments<E>>,
    /// This is an array of optional blob tree hash roots, each index in the array corresponding
    /// to the blob index. On insertion, a collision at an index here when `required_blobs` is
    /// `None` means we need to construct an entirely new `Data` entry. This is because we have
    /// no way of knowing which blob is the correct one until we see the block.
    processing_blobs: Vec<KzgCommitment>,
}

impl<E: EthSpec> SimplifiedPendingComponents<E> {
    pub fn get_missing_blob_info(&self) -> MissingBlobInfo<E> {
        todo!()
    }
}

impl<E: EthSpec> ProcessingCache<E> {
    pub fn put_processed(&mut self, block_root: Hash256) -> bool {
        self.processed_cache.insert(block_root)
    }

    pub fn has_block(&self, block_root: &Hash256) -> bool {
        self.processed_cache.contains(block_root)
            || self
                .processing_cache
                .get(block_root)
                .map_or(false, |b| b.kzg_commitments.is_some())
    }

    pub fn peek(&self, block_root: &Hash256) -> Option<&SimplifiedPendingComponents<E>> {
        self.processing_cache.get(block_root)
    }

    pub fn get_missing_blob_ids(&self) -> Vec<BlobIdentifier> {
        todo!()
    }

    pub fn remove_processing(&mut self, block_root: Hash256) {
        todo!()
    }

    pub fn prune(&mut self, slot: Slot) {
        todo!()
    }
}
