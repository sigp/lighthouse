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
use super::network_context::SyncNetworkContext;
use super::peer_sync_info::{remote_sync_type, PeerSyncType};
use super::range_sync::{RangeSync, RangeSyncType, EPOCHS_PER_BATCH};
use crate::beacon_processor::{ChainSegmentProcessId, WorkEvent as BeaconWorkEvent};
use crate::service::NetworkMessage;
use crate::status::ToStatusMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockError, EngineState};
use futures::StreamExt;
use lighthouse_network::rpc::methods::MAX_REQUEST_BLOCKS;
use lighthouse_network::types::{NetworkGlobals, SyncState};
use lighthouse_network::SyncInfo;
use lighthouse_network::{PeerAction, PeerId};
use slog::{crit, debug, error, info, trace, Logger};
use std::boxed::Box;
use std::ops::Sub;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use types::{BlobsSidecar, EthSpec, Hash256, SignedBeaconBlock, Slot};

/// The number of slots ahead of us that is allowed before requesting a long-range (batch)  Sync
/// from a peer. If a peer is within this tolerance (forwards or backwards), it is treated as a
/// fully sync'd peer.
///
/// This means that we consider ourselves synced (and hence subscribe to all subnets and block
/// gossip if no peers are further than this range ahead of us that we have not already downloaded
/// blocks for.
pub const SLOT_IMPORT_TOLERANCE: usize = 32;

pub type Id = u32;

/// Id of rpc requests sent by sync to the network.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum RequestId {
    /// Request searching for a block given a hash.
    SingleBlock { id: Id },
    /// Request searching for a block's parent. The id is the chain
    ParentLookup { id: Id },
    /// Request was from the backfill sync algorithm.
    BackFillSync { id: Id },
    /// The request was from a chain in the range sync algorithm.
    RangeSync { id: Id },
}

#[derive(Debug)]
/// A message than can be sent to the sync manager thread.
pub enum SyncMessage<T: EthSpec> {
    /// A useful peer has been discovered.
    AddPeer(PeerId, SyncInfo),

    /// A block has been received from the RPC.
    RpcBlock {
        request_id: RequestId,
        peer_id: PeerId,
        beacon_block: Option<Arc<SignedBeaconBlock<T>>>,
        seen_timestamp: Duration,
    },

    /// A blob has been received from RPC.
    RpcBlob {
        peer_id: PeerId,
        request_id: RequestId,
        blob_sidecar: Option<Arc<BlobsSidecar<T>>>,
        seen_timestamp: Duration,
    },

    /// A block with an unknown parent has been received.
    UnknownBlock(PeerId, Arc<SignedBeaconBlock<T>>, Hash256),

    /// A peer has sent an object that references a block that is unknown. This triggers the
    /// manager to attempt to find the block matching the unknown hash.
    UnknownBlockHash(PeerId, Hash256),

    /// A peer has disconnected.
    Disconnect(PeerId),

    /// An RPC Error has occurred on a request.
    RpcError {
        peer_id: PeerId,
        request_id: RequestId,
    },

    /// A batch has been processed by the block processor thread.
    BatchProcessed {
        sync_type: ChainSegmentProcessId,
        result: BatchProcessResult,
    },

    /// Block processed
    BlockProcessed {
        process_type: BlockProcessType,
        result: BlockProcessResult<T>,
    },
}

/// The type of processing specified for a received block.
#[derive(Debug, Clone)]
pub enum BlockProcessType {
    SingleBlock { id: Id },
    ParentLookup { chain_hash: Hash256 },
}

#[derive(Debug)]
pub enum BlockProcessResult<T: EthSpec> {
    Ok,
    Err(BlockError<T>),
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

    /// A reference to the network globals and peer-db.
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,

    /// A receiving channel sent by the message processor thread.
    input_channel: mpsc::UnboundedReceiver<SyncMessage<T::EthSpec>>,

    /// A network context to contact the network service.
    network: SyncNetworkContext<T>,

    /// The object handling long-range batch load-balanced syncing.
    range_sync: RangeSync<T>,

    /// Backfill syncing.
    backfill_sync: BackFillSync<T>,

    block_lookups: BlockLookups<T>,

    /// The logger for the import manager.
    log: Logger,
}

/// Spawns a new `SyncManager` thread which has a weak reference to underlying beacon
/// chain. This allows the chain to be
/// dropped during the syncing process which will gracefully end the `SyncManager`.
pub fn spawn<T: BeaconChainTypes>(
    executor: task_executor::TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T>>,
    log: slog::Logger,
) -> mpsc::UnboundedSender<SyncMessage<T::EthSpec>> {
    assert!(
        MAX_REQUEST_BLOCKS >= T::EthSpec::slots_per_epoch() * EPOCHS_PER_BATCH,
        "Max blocks that can be requested in a single batch greater than max allowed blocks in a single request"
    );
    // generate the message channel
    let (sync_send, sync_recv) = mpsc::unbounded_channel::<SyncMessage<T::EthSpec>>();

    // create an instance of the SyncManager
    let mut sync_manager = SyncManager {
        chain: beacon_chain.clone(),
        network_globals: network_globals.clone(),
        input_channel: sync_recv,
        network: SyncNetworkContext::new(
            network_send,
            network_globals.clone(),
            beacon_processor_send,
            log.clone(),
        ),
        range_sync: RangeSync::new(beacon_chain.clone(), log.clone()),
        backfill_sync: BackFillSync::new(beacon_chain, network_globals, log.clone()),
        block_lookups: BlockLookups::new(log.clone()),
        log: log.clone(),
    };

    // spawn the sync manager thread
    debug!(log, "Sync Manager started");
    executor.spawn(async move { Box::pin(sync_manager.main()).await }, "sync");
    sync_send
}

impl<T: BeaconChainTypes> SyncManager<T> {
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
    fn inject_error(&mut self, peer_id: PeerId, request_id: RequestId) {
        trace!(self.log, "Sync manager received a failed RPC");
        match request_id {
            RequestId::SingleBlock { id } => {
                self.block_lookups
                    .single_block_lookup_failed(id, &mut self.network);
            }
            RequestId::ParentLookup { id } => {
                self.block_lookups
                    .parent_lookup_failed(id, peer_id, &mut self.network);
            }
            RequestId::BackFillSync { id } => {
                if let Some(batch_id) = self.network.backfill_sync_response(id, true) {
                    match self
                        .backfill_sync
                        .inject_error(&mut self.network, batch_id, &peer_id, id)
                    {
                        Ok(_) => {}
                        Err(_) => self.update_sync_state(),
                    }
                }
            }
            RequestId::RangeSync { id } => {
                if let Some((chain_id, batch_id)) = self.network.range_sync_response(id, true) {
                    self.range_sync.inject_error(
                        &mut self.network,
                        peer_id,
                        batch_id,
                        chain_id,
                        id,
                    );
                    self.update_sync_state()
                }
            }
        }
    }

    fn peer_disconnect(&mut self, peer_id: &PeerId) {
        self.range_sync.peer_disconnect(&mut self.network, peer_id);
        self.block_lookups
            .peer_disconnected(peer_id, &mut self.network);
        // Regardless of the outcome, we update the sync status.
        let _ = self
            .backfill_sync
            .peer_disconnected(peer_id, &mut self.network);
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
            .network_globals
            .peers
            .write()
            .update_sync_status(peer_id, new_state.clone());
        if let Some(was_updated) = update_sync_status {
            let is_connected = self.network_globals.peers.read().is_connected(peer_id);
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

                        let peers = self.network_globals.peers.read();
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
                    self.backfill_sync.pause();

                    SyncState::SyncingFinalized {
                        start_slot,
                        target_slot,
                    }
                }
                Some((RangeSyncType::Head, start_slot, target_slot)) => {
                    // If there is a backfill sync in progress pause it.
                    self.backfill_sync.pause();

                    SyncState::SyncingHead {
                        start_slot,
                        target_slot,
                    }
                }
            },
        };

        let old_state = self.network_globals.set_sync_state(new_state);
        let new_state = self.network_globals.sync_state.read();
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

        // process any inbound messages
        loop {
            tokio::select! {
                Some(sync_message) = self.input_channel.recv() => {
                    self.handle_message(sync_message);
                },
                Some(engine_state) = check_ee_stream.next(), if check_ee => {
                    self.handle_new_execution_engine_state(engine_state);
                }
            }
        }
    }

    fn handle_message(&mut self, sync_message: SyncMessage<T::EthSpec>) {
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
            SyncMessage::UnknownBlock(peer_id, block, block_root) => {
                // If we are not synced or within SLOT_IMPORT_TOLERANCE of the block, ignore
                if !self.network_globals.sync_state.read().is_synced() {
                    let head_slot = self.chain.canonical_head.cached_head().head_slot();
                    let unknown_block_slot = block.slot();

                    // if the block is far in the future, ignore it. If its within the slot tolerance of
                    // our current head, regardless of the syncing state, fetch it.
                    if (head_slot >= unknown_block_slot
                        && head_slot.sub(unknown_block_slot).as_usize() > SLOT_IMPORT_TOLERANCE)
                        || (head_slot < unknown_block_slot
                            && unknown_block_slot.sub(head_slot).as_usize() > SLOT_IMPORT_TOLERANCE)
                    {
                        return;
                    }
                }
                if self.network_globals.peers.read().is_connected(&peer_id)
                    && self.network.is_execution_engine_online()
                {
                    self.block_lookups
                        .search_parent(block_root, block, peer_id, &mut self.network);
                }
            }
            SyncMessage::UnknownBlockHash(peer_id, block_hash) => {
                // If we are not synced, ignore this block.
                if self.network_globals.sync_state.read().is_synced()
                    && self.network_globals.peers.read().is_connected(&peer_id)
                    && self.network.is_execution_engine_online()
                {
                    self.block_lookups
                        .search_block(block_hash, peer_id, &mut self.network);
                }
            }
            SyncMessage::Disconnect(peer_id) => {
                self.peer_disconnect(&peer_id);
            }
            SyncMessage::RpcError {
                peer_id,
                request_id,
            } => self.inject_error(peer_id, request_id),
            SyncMessage::BlockProcessed {
                process_type,
                result,
            } => match process_type {
                BlockProcessType::SingleBlock { id } => {
                    self.block_lookups
                        .single_block_processed(id, result, &mut self.network)
                }
                BlockProcessType::ParentLookup { chain_hash } => self
                    .block_lookups
                    .parent_block_processed(chain_hash, result, &mut self.network),
            },
            SyncMessage::BatchProcessed { sync_type, result } => match sync_type {
                ChainSegmentProcessId::RangeBatchId(chain_id, epoch, _) => {
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
                ChainSegmentProcessId::ParentLookup(chain_hash) => self
                    .block_lookups
                    .parent_chain_processed(chain_hash, result, &mut self.network),
            },
            //FIXME(sean)
            SyncMessage::RpcBlob { .. } => todo!(),
        }
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

                // - Parent lookups:
                //   Disabled while in this state. We drop current requests and don't search for new
                //   blocks.
                let dropped_parent_chain_requests = self.block_lookups.drop_parent_chain_requests();

                // - Range:
                //   We still send found peers to range so that it can keep track of potential chains
                //   with respect to our current peers. Range will stop processing batches in the
                //   meantime. No further action from the manager is required for this.

                // - Backfill: Not affected by ee states, nothing to do.

                // Some logs.
                if dropped_single_blocks_requests > 0 || dropped_parent_chain_requests > 0 {
                    debug!(self.log, "Execution engine not online, dropping active requests.";
                        "dropped_single_blocks_requests" => dropped_single_blocks_requests,
                        "dropped_parent_chain_requests" => dropped_parent_chain_requests,
                    );
                }
            }
        }
    }

    fn rpc_block_received(
        &mut self,
        request_id: RequestId,
        peer_id: PeerId,
        beacon_block: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
        seen_timestamp: Duration,
    ) {
        match request_id {
            RequestId::SingleBlock { id } => self.block_lookups.single_block_lookup_response(
                id,
                peer_id,
                beacon_block,
                seen_timestamp,
                &mut self.network,
            ),
            RequestId::ParentLookup { id } => self.block_lookups.parent_lookup_response(
                id,
                peer_id,
                beacon_block,
                seen_timestamp,
                &mut self.network,
            ),
            RequestId::BackFillSync { id } => {
                if let Some(batch_id) = self
                    .network
                    .backfill_sync_response(id, beacon_block.is_none())
                {
                    match self.backfill_sync.on_block_response(
                        &mut self.network,
                        batch_id,
                        &peer_id,
                        id,
                        beacon_block,
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
            RequestId::RangeSync { id } => {
                if let Some((chain_id, batch_id)) =
                    self.network.range_sync_response(id, beacon_block.is_none())
                {
                    self.range_sync.blocks_by_range_response(
                        &mut self.network,
                        peer_id,
                        chain_id,
                        batch_id,
                        id,
                        beacon_block,
                    );
                    self.update_sync_state();
                }
            }
        }
    }
}

impl<IgnoredOkVal, T: EthSpec> From<Result<IgnoredOkVal, BlockError<T>>> for BlockProcessResult<T> {
    fn from(result: Result<IgnoredOkVal, BlockError<T>>) -> Self {
        match result {
            Ok(_) => BlockProcessResult::Ok,
            Err(e) => e.into(),
        }
    }
}

impl<T: EthSpec> From<BlockError<T>> for BlockProcessResult<T> {
    fn from(e: BlockError<T>) -> Self {
        BlockProcessResult::Err(e)
    }
}
