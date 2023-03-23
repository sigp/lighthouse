use crate::blob_verification::{
    verify_kzg_for_blob, AvailableBlock, BlockWrapper, GossipVerifiedBlob, KzgVerifiedBlob,
    KzgVerifiedBlobList,
};
use crate::block_verification::{AvailableExecutedBlock, ExecutedBlock};

use kzg::Error as KzgError;
use kzg::Kzg;
use parking_lot::{Mutex, RwLock};
use ssz_types::Error;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use types::blob_sidecar::{BlobIdentifier, BlobSidecar};
use types::{Epoch, EthSpec, Hash256};

#[derive(Debug)]
pub enum AvailabilityCheckError {
    DuplicateBlob(Hash256),
    Kzg(KzgError),
    KzgVerificationFailed,
    KzgNotInitialized,
    SszTypes(ssz_types::Error),
    MissingBlobs,
    NumBlobsMismatch {
        num_kzg_commitments: usize,
        num_blobs: usize,
    },
    TxKzgCommitmentMismatch,
    KzgCommitmentMismatch {
        blob_index: u64,
    },
    Pending,
    IncorrectFork,
}

impl From<ssz_types::Error> for AvailabilityCheckError {
    fn from(value: Error) -> Self {
        Self::SszTypes(value)
    }
}

/// This cache contains
///  - blobs that have been gossip verified
///  - commitments for blocks that have been gossip verified, but the commitments themselves
///    have not been verified against blobs
///  - blocks that have been fully verified and only require a data availability check
pub struct DataAvailabilityChecker<T: EthSpec> {
    rpc_blob_cache: RwLock<HashMap<BlobIdentifier, Arc<BlobSidecar<T>>>>,
    gossip_blob_cache: Mutex<HashMap<Hash256, GossipBlobCache<T>>>,
    kzg: Option<Arc<Kzg>>,
}

pub enum Availability<T: EthSpec> {
    PendingBlobs(Vec<BlobIdentifier>),
    PendingBlock(Hash256),
    Available(Box<AvailableExecutedBlock<T>>),
}

struct GossipBlobCache<T: EthSpec> {
    verified_blobs: Vec<KzgVerifiedBlob<T>>,
    executed_block: Option<ExecutedBlock<T>>,
}

impl<T: EthSpec> DataAvailabilityChecker<T> {
    pub fn new(kzg: Option<Arc<Kzg>>) -> Self {
        Self {
            rpc_blob_cache: <_>::default(),
            gossip_blob_cache: <_>::default(),
            kzg,
        }
    }

    /// Validate the KZG commitment included in the blob sidecar.
    /// Check if we've cached other blobs for this block. If it completes a set and we also
    /// have a block cached, import the block. Otherwise cache the blob sidecar.
    ///
    /// This should only accept gossip verified blobs, so we should not have to worry about dupes.
    pub fn put_blob(
        &self,
        verified_blob: GossipVerifiedBlob<T>,
        da_check_fn: impl FnOnce(Epoch) -> bool,
    ) -> Result<Availability<T>, AvailabilityCheckError> {
        let block_root = verified_blob.block_root();

        let kzg_verified_blob = if let Some(kzg) = self.kzg.as_ref() {
            verify_kzg_for_blob(verified_blob, kzg)?
        } else {
            return Err(AvailabilityCheckError::KzgNotInitialized);
        };

        //TODO(sean) can we just use a referece to the blob here?
        let blob = kzg_verified_blob.clone_blob();

        // check if we have a block
        // check if the complete set matches the block
        // verify, otherwise cache

        let mut blob_cache = self.gossip_blob_cache.lock();

        // Gossip cache.
        let availability = match blob_cache.entry(blob.block_root) {
            Entry::Occupied(mut occupied_entry) => {
                // All blobs reaching this cache should be gossip verified and gossip verification
                // should filter duplicates, as well as validate indices.
                let cache = occupied_entry.get_mut();

                cache
                    .verified_blobs
                    .insert(blob.index as usize, kzg_verified_blob);

                if let Some(executed_block) = cache.executed_block.take() {
                    let ExecutedBlock {
                        block: block_wrapper,
                        import_data,
                        payload_verification_outcome,
                    } = executed_block;
                    match block_wrapper {
                        BlockWrapper::AvailabilityPending(block) => {
                            let kzg_commitments = block
                                .message_eip4844()
                                .map_err(|_| AvailabilityCheckError::IncorrectFork)?
                                .body
                                .blob_kzg_commitments
                                .clone()
                                .to_vec();
                            let verified_commitments: Vec<_> = cache
                                .verified_blobs
                                .iter()
                                .map(|blob| blob.kzg_commitment())
                                .collect();
                            if verified_commitments == kzg_commitments {
                                //TODO(sean) can we remove this clone
                                let blobs = cache.verified_blobs.clone();
                                let available_block = AvailableBlock::new(
                                    block,
                                    blobs,
                                    da_check_fn,
                                    self.kzg.clone(),
                                )?;
                                Availability::Available(Box::new(AvailableExecutedBlock::new(
                                    available_block,
                                    import_data,
                                    payload_verification_outcome,
                                )))
                            } else {
                                let mut missing_blobs = Vec::with_capacity(kzg_commitments.len());
                                for i in 0..kzg_commitments.len() {
                                    if cache.verified_blobs.get(i).is_none() {
                                        missing_blobs.push(BlobIdentifier {
                                            block_root: import_data.block_root,
                                            index: i as u64,
                                        })
                                    }
                                }

                                let _ = cache.executed_block.insert(ExecutedBlock::new(
                                    BlockWrapper::AvailabilityPending(block),
                                    import_data,
                                    payload_verification_outcome,
                                ));

                                Availability::PendingBlobs(missing_blobs)
                            }
                        }
                        BlockWrapper::Available(_available_block) => {
                            // log warn, shouldn't have cached this
                            todo!()
                        }
                        BlockWrapper::AvailabilityCheckDelayed(_block, _blobs) => {
                            // log warn, shouldn't have cached this
                            todo!()
                        }
                    }
                } else {
                    Availability::PendingBlock(block_root)
                }
            }
            Entry::Vacant(vacant_entry) => {
                let block_root = kzg_verified_blob.block_root();
                vacant_entry.insert(GossipBlobCache {
                    verified_blobs: vec![kzg_verified_blob],
                    executed_block: None,
                });
                Availability::PendingBlock(block_root)
            }
        };

        drop(blob_cache);

        // RPC cache.
        self.rpc_blob_cache.write().insert(blob.id(), blob.clone());

        Ok(availability)
    }

    // return an enum here that may include the full block
    pub fn check_block_availability(
        &self,
        executed_block: ExecutedBlock<T>,
        da_check_fn: impl FnOnce(Epoch) -> bool,
    ) -> Result<Availability<T>, AvailabilityCheckError> {
        let kzg = self.kzg.clone();

        let ExecutedBlock {
            block,
            import_data,
            payload_verification_outcome,
        } = executed_block;

        let availability = match block {
            BlockWrapper::Available(available) => Availability::Available(Box::new(
                AvailableExecutedBlock::new(available, import_data, payload_verification_outcome),
            )),
            BlockWrapper::AvailabilityPending(block) => {
                if let Ok(kzg_commitments) = block.message().body().blob_kzg_commitments() {
                    let mut guard = self.gossip_blob_cache.lock();
                    let entry = guard.entry(import_data.block_root);

                    match entry {
                        Entry::Occupied(mut occupied_entry) => {
                            let cache: &mut GossipBlobCache<T> = occupied_entry.get_mut();

                            let verified_commitments: Vec<_> = cache
                                .verified_blobs
                                .iter()
                                .map(|blob| blob.kzg_commitment())
                                .collect();
                            if verified_commitments == kzg_commitments.clone().to_vec() {
                                let removed: GossipBlobCache<T> = occupied_entry.remove();

                                let available_block = AvailableBlock::new(
                                    block,
                                    removed.verified_blobs,
                                    da_check_fn,
                                    kzg,
                                )?;

                                let available_executed = AvailableExecutedBlock::new(
                                    available_block,
                                    import_data,
                                    payload_verification_outcome,
                                );
                                Availability::Available(Box::new(available_executed))
                            } else {
                                let mut missing_blobs = Vec::with_capacity(kzg_commitments.len());
                                for i in 0..kzg_commitments.len() {
                                    if cache.verified_blobs.get(i).is_none() {
                                        missing_blobs.push(BlobIdentifier {
                                            block_root: import_data.block_root,
                                            index: i as u64,
                                        })
                                    }
                                }

                                //TODO(sean) add a check that missing blobs > 0

                                let _ = cache.executed_block.insert(ExecutedBlock::new(
                                    BlockWrapper::AvailabilityPending(block),
                                    import_data,
                                    payload_verification_outcome,
                                ));
                                // log that we cached the block?
                                Availability::PendingBlobs(missing_blobs)
                            }
                        }
                        Entry::Vacant(vacant_entry) => {
                            let mut blob_ids = Vec::with_capacity(kzg_commitments.len());
                            for i in 0..kzg_commitments.len() {
                                blob_ids.push(BlobIdentifier {
                                    block_root: import_data.block_root,
                                    index: i as u64,
                                });
                            }

                            vacant_entry.insert(GossipBlobCache {
                                verified_blobs: vec![],
                                executed_block: Some(ExecutedBlock::new(
                                    BlockWrapper::AvailabilityPending(block),
                                    import_data,
                                    payload_verification_outcome,
                                )),
                            });

                            Availability::PendingBlobs(blob_ids)
                        }
                    }
                } else {
                    let blob_list: KzgVerifiedBlobList<T> = vec![];
                    Availability::Available(Box::new(AvailableExecutedBlock::new(
                        AvailableBlock::new(block, blob_list, da_check_fn, kzg)?,
                        import_data,
                        payload_verification_outcome,
                    )))
                }
            }
            BlockWrapper::AvailabilityCheckDelayed(block, blobs) => {
                //TODO(sean) shouldn't need to touch the cache here, maybe we should check if any blobs/blocks should
                // be purged though?
                Availability::Available(Box::new(AvailableExecutedBlock::new(
                    AvailableBlock::new(block, blobs, da_check_fn, kzg)?,
                    import_data,
                    payload_verification_outcome,
                )))
            }
        };
        Ok(availability)
    }
}
