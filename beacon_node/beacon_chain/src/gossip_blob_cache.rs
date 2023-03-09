use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use parking_lot::{Mutex, RwLock};
use kzg::KzgCommitment;
use ssz_types::VariableList;
use types::blob_sidecar::{BlobIdentifier, BlobSidecar};
use types::{EthSpec, Hash256};
use crate::blob_verification::{AvailabilityPendingBlock, verify_data_availability};
use crate::block_verification::IntoExecutionPendingBlock;

/// This cache contains
///  - blobs that have been gossip verified
///  - commitments for blocks that have been gossip verified, but the commitments themselves
///    have not been verified against blobs
///  - blocks that have been fully verified and only require a data availability check
pub struct GossipBlobCache<T: EthSpec> {
    blob_cache: Mutex<GossipBlobCacheInner<T>>
}

struct GossipBlobCacheInner<T: EthSpec> {
    // used when all blobs are not yet present and when the block is not yet present

    //TODO(sean) do we want two versions of this cache, one meant to serve RPC?
    unverified_blobs: BTreeMap<BlobIdentifier, Arc<BlobSidecar<T>>>,
    // used when the block was fully processed before we received all blobs
    availability_pending_blocks: HashMap<Hash256, AvailabilityPendingBlock<T>>,
    // used to cache kzg commitments from gossip verified blocks in case we receive all blobs during block processing
    unverified_commitments: HashMap<Hash256, VariableList<KzgCommitment, T::MaxBlobsPerBlock>>,
    // used when block + blob kzg verification completes prior before block processing
    verified_commitments: HashSet<Hash256>,
}

impl <T: EthSpec> GossipBlobCache<T> {
    pub fn new() -> Self {

        Self {
            blob_cache: Mutex::new(GossipBlobCacheInner {
                unverified_blobs:  BTreeMap::new(),
                availability_pending_blocks:  HashMap::new(),
                unverified_commitments: HashMap::new(),
                verified_commitments: HashSet::new(),
            })
        }

    }

    /// When we receive a blob check if we've cached it. If it completes a set and we have the
    /// corresponding commitments, verify the commitments. If it completes a set and we have a block
    /// cached, verify the block and import it.
    ///
    /// This should only accept gossip verified blobs, so we should not have to worry about dupes.
    pub fn put_blob(&self, blob: Arc<BlobSidecar<T>>) {
        let blob_id = blob.id();
        let blob_cache = self.blob_cache.lock();

        if let Some(dup) = blob_cache.unverified_blobs.insert(blob_id, blob) {
            // return error relating to gossip validation failure
        }

        if let Some(availability_pending_block) = blob_cache.availability_pending_blocks.get(&blob.block_root) {
            let num_blobs = availability_pending_block.kzg_commitments().len();
            let mut blobs : Vec<BlobIdentifier, BlobSidecar<T>> = blob_cache.unverified_blobs.range(BlobIdentifier::new(blob.block_root, 0)
                ..BlobIdentifier::new(blob.block_root, num_blobs as u64)).collect();

            if blobs.len() == num_blobs {
               // verify
                // import
            }
        } else if let Some(commitments) = blob_cache.unverified_commitments.get(&blob.block_root) {
            let num_blobs = commitments.len();
            let mut blobs : Vec<BlobIdentifier, BlobSidecar<T>> = blob_cache.unverified_blobs.range(BlobIdentifier::new(blob.block_root, 0)
                ..BlobIdentifier::new(blob.block_root, num_blobs as u64)).collect();

            if blobs.len() == num_blobs {
                // verify
                // cache
            }
        }
    }


    pub fn put_commitments(&self, block_root: Hash256, kzg_commitments: VariableList<KzgCommitment, T::MaxBlobsPerBlock>) {
        let blob_cache = self.blob_cache.lock();
        if let Some(dup) = blob_cache.unverified_commitments.insert(block_root, kzg_commitments) {
            // return error relating to gossip validation failure
        }

        let num_blobs = commitments.len();
        let mut blobs : Vec<BlobIdentifier, BlobSidecar<T>> = blob_cache.unverified_blobs.range(BlobIdentifier::new(blob.block_root, 0)
            ..BlobIdentifier::new(blob.block_root, num_blobs as u64)).collect();

        if blobs.len() == num_blobs {
            // verify
            // cache
        }
    }

    pub fn check_availability_and_import(&self, block_root: Hash256, block: AvailabilityPendingBlock<T>) -> bool {
        let blob_cache = self.blob_cache.lock();
       if blob_cache.verified_commitments.contains(&block_root) {
          true
       } else {
           // cache the block
            false
       }
    }
}
