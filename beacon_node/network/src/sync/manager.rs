//! The `SyncManager` facilities the block syncing logic of lighthouse. The current networking
//! specification provides two methods from which to obtain blocks from peers. The `BlocksByRange`
//! request and the `BlocksByRoot` request. The former is used to obtain a large number of
//! blocks and the latter allows for searching for blocks given a block-hash.
//!
//! These two RPC methods are designed for two type of syncing.
//! - Long range (batch) sync, when a client is out of date and needs to the latest head.
//! - Parent lookup - when a peer provides us a block whose parent is unknown to us.
//!
//! Both of these syncing strategies are built into the `SyncManager`.
//!
//! Currently the long-range (batch) syncing method functions by opportunistically downloading
//! batches blocks from all peers who know about a chain that we do not. When a new peer connects
//! which has a later head that is greater than `SLOT_IMPORT_TOLERANCE` from our current head slot,
//! the manager's state becomes `Syncing` and begins a batch syncing process with this peer. If
//! further peers connect, this process is run in parallel with those peers, until our head is
//! within `SLOT_IMPORT_TOLERANCE` of all connected peers.
//!
//! ## Batch Syncing
//!
//! See `RangeSync` for further details.
//!
//! ## Parent Lookup
//!
//! When a block with an unknown parent is received and we are in `Regular` sync mode, the block is
//! queued for lookup. A round-robin approach is used to request the parent from the known list of
//! fully sync'd peers. If `PARENT_FAIL_TOLERANCE` attempts at requesting the block fails, we
//! drop the propagated block and downvote the peer that sent it to us.
//!
//! Block Lookup
//!
//! To keep the logic maintained to the syncing thread (and manage the request_ids), when a block
//! needs to be searched for (i.e if an attestation references an unknown block) this manager can
//! search for the block and subsequently search for parents if needed.

use super::backfill_sync::{BackFillSync, ProcessResult, SyncStart};
use super::block_lookups::BlockLookups;
use super::network_context::{BlockOrBlob, RangeRequestId, RpcEvent, SyncNetworkContext};
use super::peer_sync_info::{remote_sync_type, PeerSyncType};
use super::range_sync::{RangeSync, RangeSyncType, EPOCHS_PER_BATCH};
use crate::network_beacon_processor::{ChainSegmentProcessId, NetworkBeaconProcessor};
use crate::service::NetworkMessage;
use crate::status::ToStatusMessage;
use crate::sync::block_lookups::{
    BlobRequestState, BlockComponent, BlockRequestState, DownloadResult,
};
use crate::sync::block_sidecar_coupling::BlocksAndBlobsRequestInfo;
use beacon_chain::block_verification_types::AsBlock;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::validator_monitor::timestamp_now;
use beacon_chain::{
    AvailabilityProcessingStatus, BeaconChain, BeaconChainTypes, BlockError, EngineState,
};
use futures::StreamExt;
use lighthouse_network::rpc::RPCError;
use lighthouse_network::types::{NetworkGlobals, SyncState};
use lighthouse_network::SyncInfo;
use lighthouse_network::{PeerAction, PeerId};
use lru_cache::LRUTimeCache;
use slog::{crit, debug, error, info, o, trace, warn, Logger};
use std::ops::Sub;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use types::{BlobSidecar, EthSpec, Hash256, SignedBeaconBlock, Slot};

/// The number of slots ahead of us that is allowed before requesting a long-range (batch)  Sync
/// from a peer. If a peer is within this tolerance (forwards or backwards), it is treated as a
/// fully sync'd peer.
///
/// This means that we consider ourselves synced (and hence subscribe to all subnets and block
/// gossip if no peers are further than this range ahead of us that we have not already downloaded
/// blocks for.
pub const SLOT_IMPORT_TOLERANCE: usize = 32;

/// Suppress duplicated `UnknownBlockHashFromAttestation` events for some duration of time. In
/// practice peers are likely to send the same root during a single slot. 30 seconds is a rather
/// arbitrary number that covers a full slot, but allows recovery if sync get stuck for a few slots.
const NOTIFIED_UNKNOWN_ROOT_EXPIRY_SECONDS: u64 = 30;

pub type Id = u32;

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct SingleLookupReqId {
    pub lookup_id: Id,
    pub req_id: Id,
}

/// Id of rpc requests sent by sync to the network.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum RequestId {
    /// Request searching for a block given a hash.
    SingleBlock { id: SingleLookupReqId },
    /// Request searching for a set of blobs given a hash.
    SingleBlob { id: SingleLookupReqId },
    /// Range request that is composed by both a block range request and a blob range request.
    RangeBlockAndBlobs { id: Id },
}

#[derive(Debug)]
/// A message that can be sent to the sync manager thread.
pub enum SyncMessage<E: EthSpec> {
    /// A useful peer has been discovered.
    AddPeer(PeerId, SyncInfo),

    /// A block has been received from the RPC.
    RpcBlock {
        request_id: RequestId,
        peer_id: PeerId,
        beacon_block: Option<Arc<SignedBeaconBlock<E>>>,
        seen_timestamp: Duration,
    },

    /// A blob has been received from the RPC.
    RpcBlob {
        request_id: RequestId,
        peer_id: PeerId,
        blob_sidecar: Option<Arc<BlobSidecar<E>>>,
        seen_timestamp: Duration,
    },

    /// A block with an unknown parent has been received.
    UnknownParentBlock(PeerId, RpcBlock<E>, Hash256),

    /// A blob with an unknown parent has been received.
    UnknownParentBlob(PeerId, Arc<BlobSidecar<E>>),

    /// A peer has sent an attestation that references a block that is unknown. This triggers the
    /// manager to attempt to find the block matching the unknown hash.
    UnknownBlockHashFromAttestation(PeerId, Hash256),

    /// A peer has disconnected.
    Disconnect(PeerId),

    /// An RPC Error has occurred on a request.
    RpcError {
        peer_id: PeerId,
        request_id: RequestId,
        error: RPCError,
    },

    /// A batch has been processed by the block processor thread.
    BatchProcessed {
        sync_type: ChainSegmentProcessId,
        result: BatchProcessResult,
    },

    /// Block processed
    BlockComponentProcessed {
        process_type: BlockProcessType,
        result: BlockProcessingResult<E>,
    },

    /// A block from gossip has completed processing,
    GossipBlockProcessResult { block_root: Hash256, imported: bool },
}

/// The type of processing specified for a received block.
#[derive(Debug, Clone)]
pub enum BlockProcessType {
    SingleBlock { id: Id },
    SingleBlob { id: Id },
}

#[derive(Debug)]
pub enum BlockProcessingResult<E: EthSpec> {
    Ok(AvailabilityProcessingStatus),
    Err(BlockError<E>),
    Ignored,
}

/// The result of processing multiple blocks (a chain segment).
#[derive(Debug)]
pub enum BatchProcessResult {
    /// The batch was completed successfully. It carries whether the sent batch contained blocks.
    Success {
        was_non_empty: bool,
    },
    /// The batch processing failed. It carries whether the processing imported any block.
    FaultyFailure {
        imported_blocks: bool,
        penalty: PeerAction,
    },
    NonFaultyFailure,
}

/// The primary object for handling and driving all the current syncing logic. It maintains the
/// current state of the syncing process, the number of useful peers, downloaded blocks and
/// controls the logic behind both the long-range (batch) sync and the on-going potential parent
/// look-up of blocks.
pub struct SyncManager<T: BeaconChainTypes> {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,

    /// A receiving channel sent by the message processor thread.
    input_channel: mpsc::UnboundedReceiver<SyncMessage<T::EthSpec>>,

    /// A network context to contact the network service.
    network: SyncNetworkContext<T>,

    /// The object handling long-range batch load-balanced syncing.
    range_sync: RangeSync<T>,

    /// Backfill syncing.
    backfill_sync: BackFillSync<T>,

    block_lookups: BlockLookups<T>,
    /// debounce duplicated `UnknownBlockHashFromAttestation` for the same root peer tuple. A peer
    /// may forward us thousands of a attestations, each one triggering an individual event. Only
    /// one event is useful, the rest generating log noise and wasted cycles
    notified_unknown_roots: LRUTimeCache<(PeerId, Hash256)>,

    /// The logger for the import manager.
    log: Logger,
}

/// Spawns a new `SyncManager` thread which has a weak reference to underlying beacon
/// chain. This allows the chain to be
/// dropped during the syncing process which will gracefully end the `SyncManager`.
pub fn spawn<T: BeaconChainTypes>(
    executor: task_executor::TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    beacon_processor: Arc<NetworkBeaconProcessor<T>>,
    sync_recv: mpsc::UnboundedReceiver<SyncMessage<T::EthSpec>>,
    log: slog::Logger,
) {
    assert!(
        beacon_chain.spec.max_request_blocks >= T::EthSpec::slots_per_epoch() * EPOCHS_PER_BATCH,
        "Max blocks that can be requested in a single batch greater than max allowed blocks in a single request"
    );

    // create an instance of the SyncManager
    let mut sync_manager = SyncManager::new(
        beacon_chain,
        network_send,
        beacon_processor,
        sync_recv,
        log.clone(),
    );

    // spawn the sync manager thread
    debug!(log, "Sync Manager started");
    executor.spawn(async move { Box::pin(sync_manager.main()).await }, "sync");
}

impl<T: BeaconChainTypes> SyncManager<T> {
    pub(crate) fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        beacon_processor: Arc<NetworkBeaconProcessor<T>>,
        sync_recv: mpsc::UnboundedReceiver<SyncMessage<T::EthSpec>>,
        log: slog::Logger,
    ) -> Self {
        let network_globals = beacon_processor.network_globals.clone();
        Self {
            chain: beacon_chain.clone(),
            input_channel: sync_recv,
            network: SyncNetworkContext::new(
                network_send,
                beacon_processor.clone(),
                beacon_chain.clone(),
                log.clone(),
            ),
            range_sync: RangeSync::new(
                beacon_chain.clone(),
                log.new(o!("service" => "range_sync")),
            ),
            backfill_sync: BackFillSync::new(
                beacon_chain.clone(),
                network_globals,
                log.new(o!("service" => "backfill_sync")),
            ),
            block_lookups: BlockLookups::new(log.new(o!("service"=> "lookup_sync"))),
            notified_unknown_roots: LRUTimeCache::new(Duration::from_secs(
                NOTIFIED_UNKNOWN_ROOT_EXPIRY_SECONDS,
            )),
            log: log.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn active_single_lookups(&self) -> Vec<super::block_lookups::BlockLookupSummary> {
        self.block_lookups.active_single_lookups()
    }

    #[cfg(test)]
    pub(crate) fn active_parent_lookups(&self) -> Vec<Vec<Hash256>> {
        self.block_lookups
            .active_parent_lookups()
            .iter()
            .map(|c| c.chain.clone())
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn get_failed_chains(&mut self) -> Vec<Hash256> {
        self.block_lookups.get_failed_chains()
    }

    #[cfg(test)]
    pub(crate) fn insert_failed_chain(&mut self, block_root: Hash256) {
        self.block_lookups.insert_failed_chain(block_root);
    }

    fn network_globals(&self) -> &NetworkGlobals<T::EthSpec> {
        self.network.network_globals()
    }

    /* Input Handling Functions */

    /// A peer has connected which has blocks that are unknown to us.
    ///
    /// This function handles the logic associated with the connection of a new peer. If the peer
    /// is sufficiently ahead of our current head, a range-sync (batch) sync is started and
    /// batches of blocks are queued to download from the peer. Batched blocks begin at our latest
    /// finalized head.
    ///
    /// If the peer is within the `SLOT_IMPORT_TOLERANCE`, then it's head is sufficiently close to
    /// ours that we consider it fully sync'd with respect to our current chain.
    fn add_peer(&mut self, peer_id: PeerId, remote: SyncInfo) {
        // ensure the beacon chain still exists
        let status = self.chain.status_message();
        let local = SyncInfo {
            head_slot: status.head_slot,
            head_root: status.head_root,
            finalized_epoch: status.finalized_epoch,
            finalized_root: status.finalized_root,
        };

        let sync_type = remote_sync_type(&local, &remote, &self.chain);

        // update the state of the peer.
        let should_add = self.update_peer_sync_state(&peer_id, &local, &remote, &sync_type);

        if matches!(sync_type, PeerSyncType::Advanced) && should_add {
            self.range_sync
                .add_peer(&mut self.network, local, peer_id, remote);
        }

        self.update_sync_state();
    }

    /// Handles RPC errors related to requests that were emitted from the sync manager.
    fn inject_error(&mut self, peer_id: PeerId, request_id: RequestId, error: RPCError) {
        trace!(self.log, "Sync manager received a failed RPC");
        match request_id {
            RequestId::SingleBlock { id } => {
                self.on_single_block_response(id, peer_id, RpcEvent::RPCError(error))
            }
            RequestId::SingleBlob { id } => {
                self.on_single_blob_response(id, peer_id, RpcEvent::RPCError(error))
            }
            RequestId::RangeBlockAndBlobs { id } => {
                if let Some(sender_id) = self.network.range_request_failed(id) {
                    match sender_id {
                        RangeRequestId::RangeSync { chain_id, batch_id } => {
                            self.range_sync.inject_error(
                                &mut self.network,
                                peer_id,
                                batch_id,
                                chain_id,
                                id,
                            );
                            self.update_sync_state();
                        }
                        RangeRequestId::BackfillSync { batch_id } => match self
                            .backfill_sync
                            .inject_error(&mut self.network, batch_id, &peer_id, id)
                        {
                            Ok(_) => {}
                            Err(_) => self.update_sync_state(),
                        },
                    }
                } else {
                    debug!(
                        self.log,
                        "RPC error for range request has no associated entry in network context, ungraceful disconnect";
                        "peer_id" => %peer_id,
                        "request_id" => %id,
                        "error" => ?error,
                    );
                }
            }
        }
    }

    /// Handles a peer disconnect.
    ///
    /// It is important that a peer disconnect retries all the batches/lookups as
    /// there is no way to guarantee that libp2p always emits a error along with
    /// the disconnect.
    fn peer_disconnect(&mut self, peer_id: &PeerId) {
        // Inject a Disconnected error on all requests associated with the disconnected peer
        // to retry all batches/lookups
        for request_id in self.network.peer_disconnected(peer_id) {
            self.inject_error(*peer_id, request_id, RPCError::Disconnected);
        }

        // Remove peer from all data structures
        self.range_sync.peer_disconnect(&mut self.network, peer_id);
        let _ = self
            .backfill_sync
            .peer_disconnected(peer_id, &mut self.network);
        self.block_lookups.peer_disconnected(peer_id);

        // Regardless of the outcome, we update the sync status.
        self.update_sync_state();
    }

    /// Updates the syncing state of a peer.
    /// Return whether the peer should be used for range syncing or not, according to its
    /// connection status.
    fn update_peer_sync_state(
        &mut self,
        peer_id: &PeerId,
        local_sync_info: &SyncInfo,
        remote_sync_info: &SyncInfo,
        sync_type: &PeerSyncType,
    ) -> bool {
        // NOTE: here we are gracefully handling two race conditions: Receiving the status message
        // of a peer that is 1) disconnected 2) not in the PeerDB.

        let new_state = sync_type.as_sync_status(remote_sync_info);
        let rpr = new_state.as_str();
        // Drop the write lock
        let update_sync_status = self
            .network_globals()
            .peers
            .write()
            .update_sync_status(peer_id, new_state.clone());
        if let Some(was_updated) = update_sync_status {
            let is_connected = self.network_globals().peers.read().is_connected(peer_id);
            if was_updated {
                debug!(
                    self.log,
                    "Peer transitioned sync state";
                    "peer_id" => %peer_id,
                    "new_state" => rpr,
                    "our_head_slot" => local_sync_info.head_slot,
                    "our_finalized_epoch" => local_sync_info.finalized_epoch,
                    "their_head_slot" => remote_sync_info.head_slot,
                    "their_finalized_epoch" => remote_sync_info.finalized_epoch,
                    "is_connected" => is_connected
                );

                // A peer has transitioned its sync state. If the new state is "synced" we
                // inform the backfill sync that a new synced peer has joined us.
                if new_state.is_synced() {
                    self.backfill_sync.fully_synced_peer_joined();
                }
            }
            is_connected
        } else {
            error!(self.log, "Status'd peer is unknown"; "peer_id" => %peer_id);
            false
        }
    }

    /// Updates the global sync state, optionally instigating or pausing a backfill sync as well as
    /// logging any changes.
    ///
    /// The logic for which sync should be running is as follows:
    /// - If there is a range-sync running (or required) pause any backfill and let range-sync
    /// complete.
    /// - If there is no current range sync, check for any requirement to backfill and either
    /// start/resume a backfill sync if required. The global state will be BackFillSync if a
    /// backfill sync is running.
    /// - If there is no range sync and no required backfill and we have synced up to the currently
    /// known peers, we consider ourselves synced.
    fn update_sync_state(&mut self) {
        let new_state: SyncState = match self.range_sync.state() {
            Err(e) => {
                crit!(self.log, "Error getting range sync state"; "error" => %e);
                return;
            }
            Ok(state) => match state {
                None => {
                    // No range sync, so we decide if we are stalled or synced.
                    // For this we check if there is at least one advanced peer. An advanced peer
                    // with Idle range is possible since a peer's status is updated periodically.
                    // If we synced a peer between status messages, most likely the peer has
                    // advanced and will produce a head chain on re-status. Otherwise it will shift
                    // to being synced
                    let mut sync_state = {
                        let head = self.chain.best_slot();
                        let current_slot = self.chain.slot().unwrap_or_else(|_| Slot::new(0));

                        let peers = self.network_globals().peers.read();
                        if current_slot >= head
                            && current_slot.sub(head) <= (SLOT_IMPORT_TOLERANCE as u64)
                            && head > 0
                        {
                            SyncState::Synced
                        } else if peers.advanced_peers().next().is_some() {
                            SyncState::SyncTransition
                        } else if peers.synced_peers().next().is_none() {
                            SyncState::Stalled
                        } else {
                            // There are no peers that require syncing and we have at least one synced
                            // peer
                            SyncState::Synced
                        }
                    };

                    // If we would otherwise be synced, first check if we need to perform or
                    // complete a backfill sync.
                    #[cfg(not(feature = "disable-backfill"))]
                    if matches!(sync_state, SyncState::Synced) {
                        // Determine if we need to start/resume/restart a backfill sync.
                        match self.backfill_sync.start(&mut self.network) {
                            Ok(SyncStart::Syncing {
                                completed,
                                remaining,
                            }) => {
                                sync_state = SyncState::BackFillSyncing {
                                    completed,
                                    remaining,
                                };
                            }
                            Ok(SyncStart::NotSyncing) => {} // Ignore updating the state if the backfill sync state didn't start.
                            Err(e) => {
                                error!(self.log, "Backfill sync failed to start"; "error" => ?e);
                            }
                        }
                    }

                    // Return the sync state if backfilling is not required.
                    sync_state
                }
                Some((RangeSyncType::Finalized, start_slot, target_slot)) => {
                    // If there is a backfill sync in progress pause it.
                    #[cfg(not(feature = "disable-backfill"))]
                    self.backfill_sync.pause();

                    SyncState::SyncingFinalized {
                        start_slot,
                        target_slot,
                    }
                }
                Some((RangeSyncType::Head, start_slot, target_slot)) => {
                    // If there is a backfill sync in progress pause it.
                    #[cfg(not(feature = "disable-backfill"))]
                    self.backfill_sync.pause();

                    SyncState::SyncingHead {
                        start_slot,
                        target_slot,
                    }
                }
            },
        };

        let old_state = self.network_globals().set_sync_state(new_state);
        let new_state = self.network_globals().sync_state.read().clone();
        if !new_state.eq(&old_state) {
            info!(self.log, "Sync state updated"; "old_state" => %old_state, "new_state" => %new_state);
            // If we have become synced - Subscribe to all the core subnet topics
            // We don't need to subscribe if the old state is a state that would have already
            // invoked this call.
            if new_state.is_synced()
                && !matches!(
                    old_state,
                    SyncState::Synced { .. } | SyncState::BackFillSyncing { .. }
                )
            {
                self.network.subscribe_core_topics();
            }
        }
    }

    /// The main driving future for the sync manager.
    async fn main(&mut self) {
        let check_ee = self.chain.execution_layer.is_some();
        let mut check_ee_stream = {
            // some magic to have an instance implementing stream even if there is no execution layer
            let ee_responsiveness_watch: futures::future::OptionFuture<_> = self
                .chain
                .execution_layer
                .as_ref()
                .map(|el| el.get_responsiveness_watch())
                .into();
            futures::stream::iter(ee_responsiveness_watch.await).flatten()
        };

        // min(LOOKUP_MAX_DURATION_*) is 15 seconds. The cost of calling prune_lookups more often is
        // one iteration over the single lookups HashMap. This map is supposed to be very small < 10
        // unless there is a bug.
        let mut prune_lookups_interval = tokio::time::interval(Duration::from_secs(15));

        // process any inbound messages
        loop {
            tokio::select! {
                Some(sync_message) = self.input_channel.recv() => {
                    self.handle_message(sync_message);
                },
                Some(engine_state) = check_ee_stream.next(), if check_ee => {
                    self.handle_new_execution_engine_state(engine_state);
                }
                _ = prune_lookups_interval.tick() => {
                    self.block_lookups.prune_lookups();
                }
            }
        }
    }

    pub(crate) fn handle_message(&mut self, sync_message: SyncMessage<T::EthSpec>) {
        match sync_message {
            SyncMessage::AddPeer(peer_id, info) => {
                self.add_peer(peer_id, info);
            }
            SyncMessage::RpcBlock {
                request_id,
                peer_id,
                beacon_block,
                seen_timestamp,
            } => {
                self.rpc_block_received(request_id, peer_id, beacon_block, seen_timestamp);
            }
            SyncMessage::RpcBlob {
                request_id,
                peer_id,
                blob_sidecar,
                seen_timestamp,
            } => self.rpc_blob_received(request_id, peer_id, blob_sidecar, seen_timestamp),
            SyncMessage::UnknownParentBlock(peer_id, block, block_root) => {
                let block_slot = block.slot();
                let parent_root = block.parent_root();
                debug!(self.log, "Received unknown parent block message"; "block_root" => %block_root, "parent_root" => %parent_root);
                self.handle_unknown_parent(
                    peer_id,
                    block_root,
                    parent_root,
                    block_slot,
                    BlockComponent::Block(DownloadResult {
                        value: block.block_cloned(),
                        block_root,
                        seen_timestamp: timestamp_now(),
                        peer_id,
                    }),
                );
            }
            SyncMessage::UnknownParentBlob(peer_id, blob) => {
                let blob_slot = blob.slot();
                let block_root = blob.block_root();
                let parent_root = blob.block_parent_root();
                debug!(self.log, "Received unknown parent blob message"; "block_root" => %block_root, "parent_root" => %parent_root);
                self.handle_unknown_parent(
                    peer_id,
                    block_root,
                    parent_root,
                    blob_slot,
                    BlockComponent::Blob(DownloadResult {
                        value: blob,
                        block_root,
                        seen_timestamp: timestamp_now(),
                        peer_id,
                    }),
                );
            }
            SyncMessage::UnknownBlockHashFromAttestation(peer_id, block_root) => {
                if !self.notified_unknown_roots.contains(&(peer_id, block_root)) {
                    self.notified_unknown_roots.insert((peer_id, block_root));
                    debug!(self.log, "Received unknown block hash message"; "block_root" => ?block_root, "peer" => ?peer_id);
                    self.handle_unknown_block_root(peer_id, block_root);
                }
            }
            SyncMessage::Disconnect(peer_id) => {
                debug!(self.log, "Received disconnected message"; "peer_id" => %peer_id);
                self.peer_disconnect(&peer_id);
            }
            SyncMessage::RpcError {
                peer_id,
                request_id,
                error,
            } => self.inject_error(peer_id, request_id, error),
            SyncMessage::BlockComponentProcessed {
                process_type,
                result,
            } => self
                .block_lookups
                .on_processing_result(process_type, result, &mut self.network),
            SyncMessage::GossipBlockProcessResult {
                block_root,
                imported,
            } => self.block_lookups.on_external_processing_result(
                block_root,
                imported,
                &mut self.network,
            ),
            SyncMessage::BatchProcessed { sync_type, result } => match sync_type {
                ChainSegmentProcessId::RangeBatchId(chain_id, epoch) => {
                    self.range_sync.handle_block_process_result(
                        &mut self.network,
                        chain_id,
                        epoch,
                        result,
                    );
                    self.update_sync_state();
                }
                ChainSegmentProcessId::BackSyncBatchId(epoch) => {
                    match self.backfill_sync.on_batch_process_result(
                        &mut self.network,
                        epoch,
                        &result,
                    ) {
                        Ok(ProcessResult::Successful) => {}
                        Ok(ProcessResult::SyncCompleted) => self.update_sync_state(),
                        Err(error) => {
                            error!(self.log, "Backfill sync failed"; "error" => ?error);
                            // Update the global status
                            self.update_sync_state();
                        }
                    }
                }
            },
        }
    }

    fn handle_unknown_parent(
        &mut self,
        peer_id: PeerId,
        block_root: Hash256,
        parent_root: Hash256,
        slot: Slot,
        block_component: BlockComponent<T::EthSpec>,
    ) {
        match self.should_search_for_block(Some(slot), &peer_id) {
            Ok(_) => {
                self.block_lookups.search_child_and_parent(
                    block_root,
                    block_component,
                    peer_id,
                    &mut self.network,
                );
            }
            Err(reason) => {
                debug!(self.log, "Ignoring unknown parent request"; "block_root" => %block_root, "parent_root" => %parent_root, "reason" => reason);
            }
        }
    }

    fn handle_unknown_block_root(&mut self, peer_id: PeerId, block_root: Hash256) {
        match self.should_search_for_block(None, &peer_id) {
            Ok(_) => {
                self.block_lookups
                    .search_unknown_block(block_root, &[peer_id], &mut self.network);
            }
            Err(reason) => {
                debug!(self.log, "Ignoring unknown block request"; "block_root" => %block_root, "reason" => reason);
            }
        }
    }

    fn should_search_for_block(
        &mut self,
        block_slot: Option<Slot>,
        peer_id: &PeerId,
    ) -> Result<(), &'static str> {
        if !self.network_globals().sync_state.read().is_synced() {
            let Some(block_slot) = block_slot else {
                return Err("not synced");
            };

            let head_slot = self.chain.canonical_head.cached_head().head_slot();

            // if the block is far in the future, ignore it. If its within the slot tolerance of
            // our current head, regardless of the syncing state, fetch it.
            if (head_slot >= block_slot
                && head_slot.sub(block_slot).as_usize() > SLOT_IMPORT_TOLERANCE)
                || (head_slot < block_slot
                    && block_slot.sub(head_slot).as_usize() > SLOT_IMPORT_TOLERANCE)
            {
                return Err("not synced");
            }
        }

        if !self.network_globals().peers.read().is_connected(peer_id) {
            return Err("peer not connected");
        }
        if !self.network.is_execution_engine_online() {
            return Err("execution engine offline");
        }
        Ok(())
    }

    fn handle_new_execution_engine_state(&mut self, engine_state: EngineState) {
        self.network.update_execution_engine_state(engine_state);

        match engine_state {
            EngineState::Online => {
                // Resume sync components.

                // - Block lookups:
                //   We start searching for blocks again. This is done by updating the stored ee online
                //   state. No further action required.

                // - Parent lookups:
                //   We start searching for parents again. This is done by updating the stored ee
                //   online state. No further action required.

                // - Range:
                //   Actively resume.
                self.range_sync.resume(&mut self.network);

                // - Backfill:
                //   Not affected by ee states, nothing to do.
            }

            EngineState::Offline => {
                // Pause sync components.

                // - Block lookups:
                //   Disabled while in this state. We drop current requests and don't search for new
                //   blocks.
                let dropped_single_blocks_requests =
                    self.block_lookups.drop_single_block_requests();

                // - Range:
                //   We still send found peers to range so that it can keep track of potential chains
                //   with respect to our current peers. Range will stop processing batches in the
                //   meantime. No further action from the manager is required for this.

                // - Backfill: Not affected by ee states, nothing to do.

                // Some logs.
                if dropped_single_blocks_requests > 0 {
                    debug!(self.log, "Execution engine not online. Dropping active requests.";
                        "dropped_single_blocks_requests" => dropped_single_blocks_requests,
                    );
                }
            }
        }
    }

    fn rpc_block_received(
        &mut self,
        request_id: RequestId,
        peer_id: PeerId,
        block: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
        seen_timestamp: Duration,
    ) {
        match request_id {
            RequestId::SingleBlock { id } => self.on_single_block_response(
                id,
                peer_id,
                match block {
                    Some(block) => RpcEvent::Response(block, seen_timestamp),
                    None => RpcEvent::StreamTermination,
                },
            ),
            RequestId::SingleBlob { .. } => {
                crit!(self.log, "Block received during blob request"; "peer_id" => %peer_id  );
            }
            RequestId::RangeBlockAndBlobs { id } => {
                self.range_block_and_blobs_response(id, peer_id, block.into())
            }
        }
    }

    fn on_single_block_response(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        block: RpcEvent<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) {
        if let Some(resp) = self.network.on_single_block_response(id, peer_id, block) {
            self.block_lookups
                .on_download_response::<BlockRequestState<T::EthSpec>>(
                    id,
                    peer_id,
                    resp,
                    &mut self.network,
                )
        }
    }

    fn rpc_blob_received(
        &mut self,
        request_id: RequestId,
        peer_id: PeerId,
        blob: Option<Arc<BlobSidecar<T::EthSpec>>>,
        seen_timestamp: Duration,
    ) {
        match request_id {
            RequestId::SingleBlock { .. } => {
                crit!(self.log, "Single blob received during block request"; "peer_id" => %peer_id  );
            }
            RequestId::SingleBlob { id } => self.on_single_blob_response(
                id,
                peer_id,
                match blob {
                    Some(blob) => RpcEvent::Response(blob, seen_timestamp),
                    None => RpcEvent::StreamTermination,
                },
            ),
            RequestId::RangeBlockAndBlobs { id } => {
                self.range_block_and_blobs_response(id, peer_id, blob.into())
            }
        }
    }

    fn on_single_blob_response(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        blob: RpcEvent<Arc<BlobSidecar<T::EthSpec>>>,
    ) {
        if let Some(resp) = self.network.on_single_blob_response(id, peer_id, blob) {
            self.block_lookups
                .on_download_response::<BlobRequestState<T::EthSpec>>(
                    id,
                    peer_id,
                    resp,
                    &mut self.network,
                )
        }
    }

    /// Handles receiving a response for a range sync request that should have both blocks and
    /// blobs.
    fn range_block_and_blobs_response(
        &mut self,
        id: Id,
        peer_id: PeerId,
        block_or_blob: BlockOrBlob<T::EthSpec>,
    ) {
        if let Some(resp) = self
            .network
            .range_block_and_blob_response(id, block_or_blob)
        {
            match resp.responses {
                Ok(blocks) => {
                    for block in blocks
                        .into_iter()
                        .map(Some)
                        // chain the stream terminator
                        .chain(vec![None])
                    {
                        match resp.sender_id {
                            RangeRequestId::RangeSync { chain_id, batch_id } => {
                                self.range_sync.blocks_by_range_response(
                                    &mut self.network,
                                    peer_id,
                                    chain_id,
                                    batch_id,
                                    id,
                                    block,
                                );
                                self.update_sync_state();
                            }
                            RangeRequestId::BackfillSync { batch_id } => {
                                match self.backfill_sync.on_block_response(
                                    &mut self.network,
                                    batch_id,
                                    &peer_id,
                                    id,
                                    block,
                                ) {
                                    Ok(ProcessResult::SyncCompleted) => self.update_sync_state(),
                                    Ok(ProcessResult::Successful) => {}
                                    Err(_error) => {
                                        // The backfill sync has failed, errors are reported
                                        // within.
                                        self.update_sync_state();
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    // Re-insert the request so we can retry
                    self.network.insert_range_blocks_and_blobs_request(
                        id,
                        resp.sender_id,
                        BlocksAndBlobsRequestInfo::new(resp.request_type, peer_id),
                    );
                    // inform range that the request needs to be treated as failed
                    // With time we will want to downgrade this log
                    warn!(
                        self.log,
                        "Blocks and blobs request for range received invalid data";
                        "peer_id" => %peer_id,
                        "sender_id" => ?resp.sender_id,
                        "error" => e.clone()
                    );
                    let id = RequestId::RangeBlockAndBlobs { id };
                    self.network.report_peer(
                        peer_id,
                        PeerAction::MidToleranceError,
                        "block_blob_faulty_batch",
                    );
                    self.inject_error(peer_id, id, RPCError::InvalidData(e))
                }
            }
        }
    }
}

impl<E: EthSpec> From<Result<AvailabilityProcessingStatus, BlockError<E>>>
    for BlockProcessingResult<E>
{
    fn from(result: Result<AvailabilityProcessingStatus, BlockError<E>>) -> Self {
        match result {
            Ok(status) => BlockProcessingResult::Ok(status),
            Err(e) => BlockProcessingResult::Err(e),
        }
    }
}

impl<E: EthSpec> From<BlockError<E>> for BlockProcessingResult<E> {
    fn from(e: BlockError<E>) -> Self {
        BlockProcessingResult::Err(e)
    }
}
