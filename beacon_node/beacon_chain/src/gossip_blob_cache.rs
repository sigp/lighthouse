use crate::blob_verification::{verify_data_availability, AsBlock};
use crate::block_verification::{ExecutedBlock, IntoExecutionPendingBlock};
use crate::kzg_utils::validate_blob;
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, BlockError};
use eth2::reqwest::header::Entry;
use kzg::Error as KzgError;
use kzg::{Kzg, KzgCommitment};
use parking_lot::{Mutex, RwLock};
use ssz_types::VariableList;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::sync::{mpsc, Arc};
use tokio::sync::mpsc::Sender;
use types::blob_sidecar::{BlobIdentifier, BlobSidecar};
use types::{EthSpec, Hash256, SignedBeaconBlock};

pub enum BlobCacheError {
    DuplicateBlob(Hash256),
    Kzg(KzgError),
}
/// This cache contains
///  - blobs that have been gossip verified
///  - commitments for blocks that have been gossip verified, but the commitments themselves
///    have not been verified against blobs
///  - blocks that have been fully verified and only require a data availability check
pub struct DataAvailabilityChecker<T: EthSpec> {
    rpc_blob_cache: RwLock<HashMap<BlobIdentifier, Arc<BlobSidecar<T>>>>,
    gossip_blob_cache: Mutex<HashMap<Hash256, GossipBlobCache<T>>>,
    kzg: Arc<Kzg>,
    tx: Sender<ExecutedBlock<T>>,
}

struct GossipBlobCache<T: EthSpec> {
    verified_blobs: Vec<Arc<BlobSidecar<T>>>,
    executed_block: Option<ExecutedBlock<T>>,
}

impl<T: EthSpec> DataAvailabilityChecker<T> {
    pub fn new(kzg: Arc<Kzg>, tx: Sender<ExecutedBlock<T>>) -> Self {
        Self {
            rpc_blob_cache: <_>::default(),
            gossip_blob_cache: <_>::default(),
            kzg,
            tx,
        }
    }

    /// When we receive a blob check if we've cached it. If it completes a set and we have the
    /// corresponding commitments, verify the commitments. If it completes a set and we have a block
    /// cached, verify the block and import it.
    ///
    /// This should only accept gossip verified blobs, so we should not have to worry about dupes.
    pub fn put_blob(&self, blob: Arc<BlobSidecar<T>>) -> Result<(), BlobCacheError> {
        // TODO(remove clones)
        let verified = validate_blob::<T>(
            &self.kzg,
            blob.blob.clone(),
            blob.kzg_commitment.clone(),
            blob.kzg_proof,
        )
        .map_err(|e| BlobCacheError::Kzg(e))?;

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
                            self.tx.try_send(executed_block);
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

        Ok(())
    }

    pub fn put_block(&self, executed_block: ExecutedBlock<T>) -> Result<(), BlobCacheError> {
        let mut guard = self.gossip_blob_cache.lock();
        guard
            .entry(executed_block.block_root)
            .and_modify(|cache| {
                let block: &SignedBeaconBlock<T> = executed_block.block.as_block();
                if let Ok(block) = block.message_eip4844() {
                    let verified_commitments: Vec<_> = cache
                        .verified_blobs
                        .iter()
                        .map(|blob| blob.kzg_commitment)
                        .collect();
                    if verified_commitments == block.body.blob_kzg_commitments.clone().to_vec() {
                        // send to reprocessing queue ?
                        //TODO(sean) errors
                        self.tx.try_send(executed_block.clone());
                    } else {
                        let _ = cache.executed_block.insert(executed_block.clone());
                        // log that we cached
                    }
                } else {
                    // log error
                }
            })
            .or_insert(GossipBlobCache {
                verified_blobs: vec![],
                executed_block: Some(executed_block),
            });

        Ok(())
    }
}
