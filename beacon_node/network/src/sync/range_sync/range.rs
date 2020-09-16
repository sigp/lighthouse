//! This contains the logic for the long range (batch) sync strategy.
//!
//! The general premise is to group peers by their self-proclaimed finalized blocks and head
//! blocks. Once grouped, the peers become sources to download a specific `Chain`. A `Chain` is a
//! collection of blocks that terminates at the specified target head.
//!
//! This sync strategy can be separated into two distinct forms:
//!  - Finalized Chain Sync
//!  - Head Chain Sync
//!
//!  ## Finalized chain sync
//!
//!  This occurs when a peer connects that claims to have a finalized head slot that is greater
//!  than our own. In this case, we form a chain from our last finalized epoch, to their claimed
//!  finalized slot. Any peer that also claims to have this last finalized slot is added to a pool
//!  of peers from which batches of blocks may be downloaded. Blocks are downloaded until the
//!  finalized slot of the chain is reached. Once reached, all peers within the pool are sent a
//!  STATUS message to potentially start a head chain sync, or check if further finalized chains
//!  need to be downloaded.
//!
//!  A few interesting notes about finalized chain syncing:
//!  - Only one finalized chain can sync at a time.
//!  - The finalized chain with the largest peer pool takes priority.
//!  - As one finalized chain completes, others are checked to see if we they can be continued,
//!  otherwise they are removed.
//!
//!  ## Head Chain Sync
//!
//!  If a peer joins and there is no active finalized chains being synced, and it's head is beyond
//!  our `SLOT_IMPORT_TOLERANCE` a chain is formed starting from this peers finalized epoch (this
//!  has been necessarily downloaded by our node, otherwise we would start a finalized chain sync)
//!  to this peers head slot. Any other peers that match this head slot and head root, are added to
//!  this chain's peer pool, which will be downloaded in parallel.
//!
//!  Unlike finalized chains, head chains can be synced in parallel.
//!
//!  ## Batch Syncing
//!
//!  Each chain is downloaded in batches of blocks. The batched blocks are processed sequentially
//!  and further batches are requested as current blocks are being processed.

use super::chain::ChainId;
use super::chain_collection::{ChainCollection, RangeSyncState};
use super::sync_type::RangeSyncType;
use crate::beacon_processor::WorkEvent as BeaconWorkEvent;
use crate::sync::network_context::SyncNetworkContext;
use crate::sync::BatchProcessResult;
use crate::sync::PeerSyncInfo;
use crate::sync::RequestId;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::{NetworkGlobals, PeerId};
use slog::{debug, error, trace};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{Epoch, EthSpec, SignedBeaconBlock};

/// The primary object dealing with long range/batch syncing. This contains all the active and
/// non-active chains that need to be processed before the syncing is considered complete. This
/// holds the current state of the long range sync.
pub struct RangeSync<T: BeaconChainTypes> {
    /// The beacon chain for processing.
    beacon_chain: Arc<BeaconChain<T>>,
    /// A collection of chains that need to be downloaded. This stores any head or finalized chains
    /// that need to be downloaded.
    chains: ChainCollection<T>,
    /// Peers that join whilst a finalized chain is being downloaded, sit in this set. Once the
    /// finalized chain(s) complete, these peer's get STATUS'ed to update their head slot before
    /// the head chains are formed and downloaded.
    awaiting_head_peers: HashSet<PeerId>,
    /// A multi-threaded, non-blocking processor for applying messages to the beacon chain.
    beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T::EthSpec>>,
    /// The syncing logger.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> RangeSync<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T::EthSpec>>,
        log: slog::Logger,
    ) -> Self {
        RangeSync {
            beacon_chain: beacon_chain.clone(),
            chains: ChainCollection::new(beacon_chain, network_globals, log.clone()),
            awaiting_head_peers: HashSet::new(),
            beacon_processor_send,
            log,
        }
    }

    /// The `chains` collection stores the current state of syncing. Once a finalized chain
    /// completes, it's state is pre-emptively set to `SyncState::Head`. This ensures that
    /// during the transition period of finalized to head, the sync manager doesn't start
    /// requesting blocks from gossipsub.
    ///
    /// On re-status, a peer that has no head to download indicates that this state can be set to
    /// idle as there are in fact no head chains to download. This function notifies the chain
    /// collection that the state can safely be set to idle.
    pub fn fully_synced_peer_found(&mut self) {
        self.chains.fully_synced_peer_found()
    }

    /// A useful peer has been added. The SyncManager has identified this peer as needing either
    /// a finalized or head chain sync. This processes the peer and starts/resumes any chain that
    /// may need to be synced as a result. A new peer, may increase the peer pool of a finalized
    /// chain, this may result in a different finalized chain from syncing as finalized chains are
    /// prioritised by peer-pool size.
    pub fn add_peer(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        peer_id: PeerId,
        remote_info: PeerSyncInfo,
    ) {
        // evaluate which chain to sync from

        // determine if we need to run a sync to the nearest finalized state or simply sync to
        // its current head

        let local_info = match PeerSyncInfo::from_chain(&self.beacon_chain) {
            Some(local) => local,
            None => {
                return error!(self.log, "Failed to get peer sync info";
                    "msg" => "likely due to head lock contention")
            }
        };

        // convenience variable
        let remote_finalized_slot = remote_info
            .finalized_epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        // NOTE: A peer that has been re-status'd may now exist in multiple finalized chains.

        // remove any out-of-date chains
        self.chains.purge_outdated_chains(network);

        // determine which kind of sync to perform and set up the chains
        match RangeSyncType::new(&self.beacon_chain, &local_info, &remote_info) {
            RangeSyncType::Finalized => {
                // Finalized chain search
                debug!(self.log, "Finalization sync peer joined"; "peer_id" => %peer_id);

                // remove the peer from the awaiting_head_peers list if it exists
                self.awaiting_head_peers.remove(&peer_id);

                // Note: We keep current head chains. These can continue syncing whilst we complete
                // this new finalized chain.

                self.chains.add_peer_or_create_chain(
                    local_info.finalized_epoch,
                    remote_info.finalized_root,
                    remote_finalized_slot,
                    peer_id,
                    RangeSyncType::Finalized,
                    &self.beacon_processor_send,
                    network,
                );

                self.chains.update(network);
                // update the global sync state
                self.chains.update_sync_state();
            }
            RangeSyncType::Head => {
                // This peer requires a head chain sync

                if self.chains.is_finalizing_sync() {
                    // If there are finalized chains to sync, finish these first, before syncing head
                    // chains. This allows us to re-sync all known peers
                    trace!(self.log, "Waiting for finalized sync to complete"; "peer_id" => %peer_id);
                    // store the peer to re-status after all finalized chains complete
                    self.awaiting_head_peers.insert(peer_id);
                    return;
                }

                // if the peer existed in any other head chain, remove it.
                self.remove_peer(network, &peer_id);

                // The new peer has the same finalized (earlier filters should prevent a peer with an
                // earlier finalized chain from reaching here).

                let start_epoch = std::cmp::min(local_info.head_slot, remote_finalized_slot)
                    .epoch(T::EthSpec::slots_per_epoch());
                self.chains.add_peer_or_create_chain(
                    start_epoch,
                    remote_info.head_root,
                    remote_info.head_slot,
                    peer_id,
                    RangeSyncType::Head,
                    &self.beacon_processor_send,
                    network,
                );
                self.chains.update(network);
                self.chains.update_sync_state();
            }
        }
    }

    /// A `BlocksByRange` response has been received from the network.
    ///
    /// This function finds the chain that made this request. Once found, processes the result.
    /// This request could complete a chain or simply add to its progress.
    pub fn blocks_by_range_response(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        _peer_id: PeerId,
        request_id: RequestId,
        beacon_block: Option<SignedBeaconBlock<T::EthSpec>>,
    ) {
        // get the chain and batch for which this response belongs
        let (chain_id, batch_id) =
            network.blocks_by_range_response(request_id, beacon_block.is_none());

        // check if this chunk removes the chain
        match self.chains.call_by_id(chain_id, |chain| {
            chain.on_block_response(network, batch_id, beacon_block)
        }) {
            Ok((removed_chain, sync_type)) => {
                if let Some(removed_chain) = removed_chain {
                    debug!(self.log, "Chain removed after block response"; "sync_type" => ?sync_type, "chain_id" => chain_id);
                    removed_chain.status_peers(network);
                    // TODO: update & update_sync_state?
                }
            }
            Err(_) => {
                debug!(self.log, "BlocksByRange response for removed chain"; "chain" => chain_id)
            }
        }
    }

    pub fn handle_block_process_result(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        chain_id: ChainId,
        batch_id: Epoch,
        result: BatchProcessResult,
    ) {
        // check if this response removes the chain
        match self.chains.call_by_id(chain_id, |chain| {
            chain.on_batch_process_result(network, batch_id, &result)
        }) {
            Ok((None, _sync_type)) => {
                // Chain was found and not removed
            }
            Ok((Some(removed_chain), sync_type)) => {
                debug!(self.log, "Chain removed after processing result"; "chain" => chain_id, "sync_type" => ?sync_type);
                // Chain ended, re-status its peers
                removed_chain.status_peers(network);
                match sync_type {
                    RangeSyncType::Finalized => {
                        // update the state of the collection
                        self.chains.update(network);
                        // set the state to a head sync if there are no finalized chains, to inform
                        // the manager that we are awaiting a head chain.
                        self.chains.set_head_sync();
                        // Update the global variables
                        self.chains.update_sync_state();
                        // if there are no more finalized chains, re-status all known peers
                        // awaiting a head sync
                        match self.chains.state() {
                            RangeSyncState::Idle | RangeSyncState::Head { .. } => {
                                network.status_peers(
                                    self.beacon_chain.clone(),
                                    self.awaiting_head_peers.drain(),
                                );
                            }
                            RangeSyncState::Finalized { .. } => {} // Have more finalized chains to complete
                        }
                    }
                    RangeSyncType::Head => {
                        // Remove non-syncing head chains and re-status the peers.  This removes a
                        // build-up of potentially duplicate head chains. Any legitimate head
                        // chains will be re-established
                        self.chains.clear_head_chains(network);
                        // update the state of the collection
                        self.chains.update(network);
                        // update the global state and log any change
                        self.chains.update_sync_state();
                    }
                }
            }

            Err(_) => {
                debug!(self.log, "BlocksByRange response for removed chain"; "chain" => chain_id)
            }
        }
    }

    /// A peer has disconnected. This removes the peer from any ongoing chains and mappings. A
    /// disconnected peer could remove a chain
    pub fn peer_disconnect(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        peer_id: &PeerId,
    ) {
        // if the peer is in the awaiting head mapping, remove it
        self.awaiting_head_peers.remove(peer_id);

        // remove the peer from any peer pool, failing its batches
        self.remove_peer(network, peer_id);

        // update the state of the collection
        self.chains.update(network);
        // update the global state and inform the user
        self.chains.update_sync_state();
    }

    /// When a peer gets removed, both the head and finalized chains need to be searched to check
    /// which pool the peer is in. The chain may also have a batch or batches awaiting
    /// for this peer. If so we mark the batch as failed. The batch may then hit it's maximum
    /// retries. In this case, we need to remove the chain and re-status all the peers.
    fn remove_peer(&mut self, network: &mut SyncNetworkContext<T::EthSpec>, peer_id: &PeerId) {
        for (removed_chain, sync_type) in self
            .chains
            .call_all(|chain| chain.remove_peer(peer_id, network))
        {
            debug!(self.log, "Chain removed"; "sync_type" => ?sync_type, "chain" => removed_chain.get_id());
            // TODO: anything else to do?
        }
    }

    /// An RPC error has occurred.
    ///
    /// Check to see if the request corresponds to a pending batch. If so, re-request it if possible, if there have
    /// been too many failed attempts for the batch, remove the chain.
    pub fn inject_error(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        _peer_id: PeerId,
        request_id: RequestId,
    ) {
        // get the chain and batch for which this response belongs
        let (chain_id, batch_id) = network.blocks_by_range_response(request_id, true);
        // check that this request is pending
        match self
            .chains
            .call_by_id(chain_id, |chain| chain.inject_error(network, batch_id))
        {
            Ok((removed_chain, sync_type)) => {
                if let Some(removed_chain) = removed_chain {
                    debug!(self.log, "Chain removed"; "sync_type" => ?sync_type, "chain" => removed_chain.get_id());
                    removed_chain.status_peers(network);
                    // TODO: update & update_sync_state?
                }
            }
            Err(_) => {
                debug!(self.log, "BlocksByRange response for removed chain"; "chain" => chain_id)
            }
        }
    }
}
