use crate::blob_verification::{
    verify_data_availability, AsBlock, AvailableBlock, BlockWrapper, VerifiedBlobs,
};
use crate::block_verification::{ExecutedBlock, IntoExecutionPendingBlock};
use crate::kzg_utils::validate_blob;
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, BlockError};
use kzg::Error as KzgError;
use kzg::{Kzg, KzgCommitment};
use parking_lot::{Mutex, RwLock};
use ssz_types::{Error, VariableList};
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::sync::{mpsc, Arc};
use tokio::sync::mpsc::Sender;
use types::blob_sidecar::{BlobIdentifier, BlobSidecar};
use types::{EthSpec, Hash256, SignedBeaconBlock, SignedBlobSidecar};

#[derive(Debug)]
pub enum AvailabilityCheckError {
    DuplicateBlob(Hash256),
    Kzg(KzgError),
    SszTypes(ssz_types::Error),
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
    Available(ExecutedBlock<T>),
}

struct GossipBlobCache<T: EthSpec> {
    verified_blobs: Vec<Arc<BlobSidecar<T>>>,
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

    /// When we receive a blob check if we've cached it. If it completes a set and we have the
    /// corresponding commitments, verify the commitments. If it completes a set and we have a block
    /// cached, verify the block and import it.
    ///
    /// This should only accept gossip verified blobs, so we should not have to worry about dupes.
    // return an enum here that may include the full block
    pub fn put_blob(
        &self,
        blob: Arc<BlobSidecar<T>>,
    ) -> Result<Availability<T>, AvailabilityCheckError> {
        let verified = if let Some(kzg) = self.kzg.as_ref() {
            validate_blob::<T>(
                kzg,
                blob.blob.clone(),
                blob.kzg_commitment.clone(),
                blob.kzg_proof,
            )
            .map_err(|e| AvailabilityCheckError::Kzg(e))?
        } else {
            false
            // error wrong fork
        };

        // TODO(remove clones)

        if verified {
            let mut blob_cache = self.gossip_blob_cache.lock();

            // Gossip cache.
            blob_cache
                .entry(blob.block_root)
                .and_modify(|mut inner| {
                    // All blobs reaching this cache should be gossip verified and gossip verification
                    // should filter duplicates, as well as validate indices.
                    inner
                        .verified_blobs
                        .insert(blob.index as usize, blob.clone());

                    if let Some(executed_block) = inner.executed_block.take() {
                        let verified_commitments: Vec<_> = inner
                            .verified_blobs
                            .iter()
                            .map(|blob| blob.kzg_commitment)
                            .collect();
                        if verified_commitments
                            == executed_block
                                .block
                                .as_block()
                                .message_eip4844()
                                .unwrap() //TODO(sean) errors
                                .body
                                .blob_kzg_commitments
                                .clone()
                                .to_vec()
                        {
                            // send to reprocessing queue ?
                            //TODO(sean) try_send?
                            //TODO(sean) errors
                        } else {
                            let _ = inner.executed_block.insert(executed_block);
                        }
                    }
                })
                .or_insert(GossipBlobCache {
                    verified_blobs: vec![blob.clone()],
                    executed_block: None,
                });

            drop(blob_cache);

            // RPC cache.
            self.rpc_blob_cache.write().insert(blob.id(), blob.clone());
        }

        Ok(Availability::PendingBlobs(vec![]))
    }

    // return an enum here that may include the full block
    pub fn check_block_availability(
        &self,
        executed_block: ExecutedBlock<T>,
    ) -> Result<Availability<T>, AvailabilityCheckError> {
        let block_clone = executed_block.block.clone();

        let availability = match block_clone {
            BlockWrapper::Available(available_block) => Availability::Available(executed_block),
            BlockWrapper::AvailabilityPending(block) => {
                if let Ok(kzg_commitments) = block.message().body().blob_kzg_commitments() {
                    // first check if the blockwrapper contains blobs, if so, use those

                    let mut guard = self.gossip_blob_cache.lock();
                    let entry = guard.entry(executed_block.block_root);

                    match entry {
                        Entry::Occupied(mut occupied_entry) => {
                            let cache: &mut GossipBlobCache<T> = occupied_entry.get_mut();

                            let verified_commitments: Vec<_> = cache
                                .verified_blobs
                                .iter()
                                .map(|blob| blob.kzg_commitment)
                                .collect();
                            if verified_commitments == kzg_commitments.clone().to_vec() {
                                let removed: GossipBlobCache<T> = occupied_entry.remove();

                                let ExecutedBlock {
                                    block: _,
                                    block_root,
                                    state,
                                    parent_block,
                                    parent_eth1_finalization_data,
                                    confirmed_state_roots,
                                    consensus_context,
                                    payload_verification_outcome,
                                } = executed_block;

                                let available_block = BlockWrapper::Available(AvailableBlock {
                                    block,
                                    blobs: VerifiedBlobs::Available(VariableList::new(
                                        removed.verified_blobs,
                                    )?),
                                });

                                let available_executed = ExecutedBlock {
                                    block: available_block,
                                    block_root,
                                    state,
                                    parent_block,
                                    parent_eth1_finalization_data,
                                    confirmed_state_roots,
                                    consensus_context,
                                    payload_verification_outcome,
                                };
                                Availability::Available(available_executed)
                            } else {
                                let mut missing_blobs = Vec::with_capacity(kzg_commitments.len());
                                for i in 0..kzg_commitments.len() {
                                    if cache.verified_blobs.get(i).is_none() {
                                        missing_blobs.push(BlobIdentifier {
                                            block_root: executed_block.block_root,
                                            index: i as u64,
                                        })
                                    }
                                }

                                //TODO(sean) add a check that missing blobs > 0

                                let _ = cache.executed_block.insert(executed_block.clone());
                                // log that we cached the block?
                                Availability::PendingBlobs(missing_blobs)
                            }
                        }
                        Entry::Vacant(vacant_entry) => {
                            let mut blob_ids = Vec::with_capacity(kzg_commitments.len());
                            for i in 0..kzg_commitments.len() {
                                blob_ids.push(BlobIdentifier {
                                    block_root: executed_block.block_root,
                                    index: i as u64,
                                });
                            }

                            vacant_entry.insert(GossipBlobCache {
                                verified_blobs: vec![],
                                executed_block: Some(executed_block),
                            });

                            Availability::PendingBlobs(blob_ids)
                        }
                    }
                } else {
                    Availability::Available(executed_block)
                }
            }
        };
        Ok(availability)
    }

    /// Adds the blob to the cache. Returns true if adding the blob completes
    /// all the required blob sidecars for a given block root.
    ///
    /// Note: we can only know this if we know `block.kzg_commitments.len()`
    pub fn put_blob_temp(
        &self,
        blob: Arc<SignedBlobSidecar<T>>,
    ) -> Result<bool, AvailabilityCheckError> {
        unimplemented!()
    }

    /// Returns all blobs associated with a given block root otherwise returns
    /// a UnavailableBlobs error.
    pub fn blobs(&self, block_root: Hash256) -> Result<VerifiedBlobs<T>, AvailabilityCheckError> {
        unimplemented!()
    }
}
