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
//!  than our own. In this case, we form a chain from our last finalized slot, to their claimed
//!  finalized slot. Any peer that also claims to have this last finalized slot is added to a pool
//!  of peers from which batches of blocks may be downloaded. Blocks are downloaded until
//!  the finalized slot of the chain is reached. Once reached, all peers within the pool are sent a
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
//!  If a peer joins and there is no active finalized chains being synced, and it's head is
//!  beyond our `SLOT_IMPORT_TOLERANCE` a chain is formed starting from this peers finalized slot
//!  (this has been necessarily downloaded by our node, otherwise we would start a finalized chain
//!  sync) to this peers head slot. Any other peers that match this head slot and head root, are
//!  added to this chain's peer pool, which will be downloaded in parallel.
//!
//!  Unlike finalized chains, head chains can be synced in parallel.
//!
//!  ## Batch Syncing
//!
//!  Each chain is downloaded in batches of blocks. The batched blocks are processed sequentially
//!  and further batches are requested as current blocks are being processed.

use super::chain::ProcessingResult;
use super::chain_collection::{ChainCollection, RangeSyncState};
use super::BatchId;
use crate::router::processor::PeerSyncInfo;
use crate::sync::block_processor::BatchProcessResult;
use crate::sync::manager::SyncMessage;
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::rpc::RequestId;
use eth2_libp2p::{NetworkGlobals, PeerId};
use slog::{debug, error, trace};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{EthSpec, SignedBeaconBlock};

/// The primary object dealing with long range/batch syncing. This contains all the active and
/// non-active chains that need to be processed before the syncing is considered complete. This
/// holds the current state of the long range sync.
pub struct RangeSync<T: BeaconChainTypes> {
    /// The beacon chain for processing.
    beacon_chain: Arc<BeaconChain<T>>,
    /// A collection of chains that need to be downloaded. This stores any head or finalized chains
    /// that need to be downloaded.
    chains: ChainCollection<T>,
    /// Peers that join whilst a finalized chain is being download, sit in this set. Once the
    /// finalized chain(s) complete, these peer's get STATUS'ed to update their head slot before
    /// the head chains are formed and downloaded.
    awaiting_head_peers: HashSet<PeerId>,
    /// The sync manager channel, allowing the batch processor thread to callback the sync task
    /// once complete.
    sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    /// The syncing logger.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> RangeSync<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
        log: slog::Logger,
    ) -> Self {
        RangeSync {
            beacon_chain: beacon_chain.clone(),
            chains: ChainCollection::new(beacon_chain, network_globals, log.clone()),
            awaiting_head_peers: HashSet::new(),
            sync_send,
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
        remote: PeerSyncInfo,
    ) {
        // evaluate which chain to sync from

        // determine if we need to run a sync to the nearest finalized state or simply sync to
        // its current head

        let local_info = match PeerSyncInfo::from_chain(&self.beacon_chain) {
            Some(local) => local,
            None => {
                return error!(
                    self.log,
                    "Failed to get peer sync info";
                    "msg" => "likely due to head lock contention"
                )
            }
        };

        // convenience variables
        let remote_finalized_slot = remote
            .finalized_epoch
            .start_slot(T::EthSpec::slots_per_epoch());
        let local_finalized_slot = local_info
            .finalized_epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        // remove peer from any chains
        self.remove_peer(network, &peer_id);

        // remove any out-of-date chains
        self.chains.purge_outdated_chains(network);

        if remote_finalized_slot > local_info.head_slot
            && !self
                .beacon_chain
                .fork_choice
                .contains_block(&remote.finalized_root)
        {
            debug!(self.log, "Finalization sync peer joined"; "peer_id" => format!("{:?}", peer_id));
            // Finalized chain search

            // Note: We keep current head chains. These can continue syncing whilst we complete
            // this new finalized chain.

            // If a finalized chain already exists that matches, add this peer to the chain's peer
            // pool.
            if let Some(chain) = self
                .chains
                .get_finalized_mut(remote.finalized_root, remote_finalized_slot)
            {
                debug!(self.log, "Finalized chain exists, adding peer"; "peer_id" => format!("{:?}", peer_id), "target_root" => format!("{}", chain.target_head_root), "end_slot" => chain.target_head_slot, "start_slot"=> chain.start_slot);

                // add the peer to the chain's peer pool
                chain.add_peer(network, peer_id);

                // check if the new peer's addition will favour a new syncing chain.
                self.chains.update_finalized(network);
            } else {
                // there is no finalized chain that matches this peer's last finalized target
                // create a new finalized chain
                debug!(self.log, "New finalized chain added to sync"; "peer_id" => format!("{:?}", peer_id), "start_slot" => local_finalized_slot.as_u64(), "end_slot" => remote_finalized_slot.as_u64(), "finalized_root" => format!("{}", remote.finalized_root));

                self.chains.new_finalized_chain(
                    local_finalized_slot,
                    remote.finalized_root,
                    remote_finalized_slot,
                    peer_id,
                    self.sync_send.clone(),
                );
                self.chains.update_finalized(network);
            }
        } else {
            if self.chains.is_finalizing_sync() {
                // If there are finalized chains to sync, finish these first, before syncing head
                // chains. This allows us to re-sync all known peers
                trace!(self.log, "Waiting for finalized sync to complete"; "peer_id" => format!("{:?}", peer_id));
                return;
            }

            // The new peer has the same finalized (earlier filters should prevent a peer with an
            // earlier finalized chain from reaching here).
            debug!(self.log, "New peer added for recent head sync"; "peer_id" => format!("{:?}", peer_id));

            // search if there is a matching head chain, then add the peer to the chain
            if let Some(chain) = self.chains.get_head_mut(remote.head_root, remote.head_slot) {
                debug!(self.log, "Adding peer to the existing head chain peer pool"; "head_root" => format!("{}",remote.head_root), "head_slot" => remote.head_slot, "peer_id" => format!("{:?}", peer_id));

                // add the peer to the head's pool
                chain.add_peer(network, peer_id);
            } else {
                // There are no other head chains that match this peer's status, create a new one, and
                let start_slot = std::cmp::min(local_info.head_slot, remote_finalized_slot);
                debug!(self.log, "Creating a new syncing head chain"; "head_root" => format!("{}",remote.head_root), "start_slot" => start_slot, "head_slot" => remote.head_slot, "peer_id" => format!("{:?}", peer_id));
                self.chains.new_head_chain(
                    network,
                    start_slot,
                    remote.head_root,
                    remote.head_slot,
                    peer_id,
                    self.sync_send.clone(),
                );
            }
            self.chains.update_finalized(network);
        }
    }

    /// A `BlocksByRange` response has been received from the network.
    ///
    /// This function finds the chain that made this request. Once found, processes the result.
    /// This request could complete a chain or simply add to its progress.
    pub fn blocks_by_range_response(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        peer_id: PeerId,
        request_id: RequestId,
        beacon_block: Option<SignedBeaconBlock<T::EthSpec>>,
    ) {
        // Find the request. Most likely the first finalized chain (the syncing chain). If there
        // are no finalized chains, then it will be a head chain. At most, there should only be
        // `connected_peers` number of head chains, which should be relatively small and this
        // lookup should not be very expensive. However, we could add an extra index that maps the
        // request id to index of the vector to avoid O(N) searches and O(N) hash lookups.

        let id_not_found = self
            .chains
            .head_finalized_request(|chain| {
                chain.on_block_response(network, request_id, &beacon_block)
            })
            .is_none();
        if id_not_found {
            // The request didn't exist in any `SyncingChain`. Could have been an old request or
            // the chain was purged due to being out of date whilst a request was pending. Log
            // and ignore.
            debug!(self.log, "Range response without matching request"; "peer" => format!("{:?}", peer_id), "request_id" => request_id);
        }
    }

    pub fn handle_block_process_result(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        batch_id: BatchId,
        downloaded_blocks: Vec<SignedBeaconBlock<T::EthSpec>>,
        result: BatchProcessResult,
    ) {
        // build an option for passing the downloaded_blocks to each chain
        let mut downloaded_blocks = Some(downloaded_blocks);

        match self.chains.finalized_request(|chain| {
            chain.on_batch_process_result(network, batch_id, &mut downloaded_blocks, &result)
        }) {
            Some((index, ProcessingResult::RemoveChain)) => {
                let chain = self.chains.remove_finalized_chain(index);
                debug!(self.log, "Finalized chain removed"; "start_slot" => chain.start_slot.as_u64(), "end_slot" => chain.target_head_slot.as_u64());
                // the chain is complete, re-status it's peers
                chain.status_peers(network);

                // update the state of the collection
                self.chains.update_finalized(network);

                // set the state to a head sync, to inform the manager that we are awaiting a
                // head chain.
                self.chains.set_head_sync();

                // if there are no more finalized chains, re-status all known peers awaiting a head
                // sync
                match self.chains.state() {
                    RangeSyncState::Idle | RangeSyncState::Head { .. } => {
                        for peer_id in self.awaiting_head_peers.drain() {
                            network.status_peer(self.beacon_chain.clone(), peer_id);
                        }
                    }
                    RangeSyncState::Finalized { .. } => {} // Have more finalized chains to complete
                }
            }
            Some((_, ProcessingResult::KeepChain)) => {}
            None => {
                match self.chains.head_request(|chain| {
                    chain.on_batch_process_result(
                        network,
                        batch_id,
                        &mut downloaded_blocks,
                        &result,
                    )
                }) {
                    Some((index, ProcessingResult::RemoveChain)) => {
                        let chain = self.chains.remove_head_chain(index);
                        debug!(self.log, "Head chain completed"; "start_slot" => chain.start_slot.as_u64(), "end_slot" => chain.target_head_slot.as_u64());
                        // the chain is complete, re-status it's peers and remove it
                        chain.status_peers(network);

                        // update the state of the collection
                        self.chains.update_finalized(network);
                    }
                    Some((_, ProcessingResult::KeepChain)) => {}
                    None => {
                        // This can happen if a chain gets purged due to being out of date whilst a
                        // batch process is in progress.
                        debug!(self.log, "No chains match the block processing id"; "id" => *batch_id);
                    }
                }
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
        self.awaiting_head_peers.remove(&peer_id);

        // remove the peer from any peer pool
        self.remove_peer(network, peer_id);

        // update the state of the collection
        self.chains.update_finalized(network);
    }

    /// When a peer gets removed, both the head and finalized chains need to be searched to check which pool the peer is in. The chain may also have a batch or batches awaiting
    /// for this peer. If so we mark the batch as failed. The batch may then hit it's maximum
    /// retries. In this case, we need to remove the chain and re-status all the peers.
    fn remove_peer(&mut self, network: &mut SyncNetworkContext<T::EthSpec>, peer_id: &PeerId) {
        if let Some((index, ProcessingResult::RemoveChain)) =
            self.chains.head_finalized_request(|chain| {
                if chain.peer_pool.remove(peer_id) {
                    // this chain contained the peer
                    while let Some(batch) = chain.pending_batches.remove_batch_by_peer(peer_id) {
                        if let ProcessingResult::RemoveChain = chain.failed_batch(network, batch) {
                            // a single batch failed, remove the chain
                            return Some(ProcessingResult::RemoveChain);
                        }
                    }
                    // peer removed from chain, no batch failed
                    Some(ProcessingResult::KeepChain)
                } else {
                    None
                }
            })
        {
            // the chain needed to be removed
            debug!(self.log, "Chain being removed due to failed batch");
            self.chains.remove_chain(network, index);
        }
    }

    /// An RPC error has occurred.
    ///
    /// Check to see if the request corresponds to a pending batch. If so, re-request it if possible, if there have
    /// been too many failed attempts for the batch, remove the chain.
    pub fn inject_error(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        peer_id: PeerId,
        request_id: RequestId,
    ) {
        // check that this request is pending
        match self
            .chains
            .head_finalized_request(|chain| chain.inject_error(network, &peer_id, request_id))
        {
            Some((_, ProcessingResult::KeepChain)) => {} // error handled chain persists
            Some((index, ProcessingResult::RemoveChain)) => {
                debug!(self.log, "Chain being removed due to RPC error");
                self.chains.remove_chain(network, index)
            }
            None => {} // request wasn't in the finalized chains, check the head chains
        }
    }
}
