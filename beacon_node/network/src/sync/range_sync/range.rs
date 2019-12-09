use super::chain::ProcessingResult;
use super::chain_collection::{ChainCollection, SyncState};
use crate::sync::message_processor::PeerSyncInfo;
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::rpc::RequestId;
use eth2_libp2p::PeerId;
use slog::{debug, trace, warn};
use std::collections::HashSet;
use std::sync::Weak;
use types::{BeaconBlock, EthSpec};

//TODO: The code becomes cleaner if finalized_chains and head_chains were merged into a single
// object. This will prevent code duplication. Rather than keeping the current syncing
// finalized chain in index 0, it should be stored in this object under an option. Then lookups can
// occur over the single object containing both finalized and head chains, which would then
// behave similarly.

pub struct RangeSync<T: BeaconChainTypes> {
    /// The beacon chain for processing
    beacon_chain: Weak<BeaconChain<T>>,
    chains: ChainCollection<T>,
    /// Known peers to the RangeSync, that need to be re-status'd once finalized chains are
    /// completed.
    awaiting_head_peers: HashSet<PeerId>,
    log: slog::Logger,
}

impl<T: BeaconChainTypes> RangeSync<T> {
    pub fn new(beacon_chain: Weak<BeaconChain<T>>, log: slog::Logger) -> Self {
        RangeSync {
            beacon_chain,
            chains: ChainCollection::new(),
            awaiting_head_peers: HashSet::new(),
            log,
        }
    }

    // Notify the collection that a fully synced peer was found. This allows updating the state
    // if we were awaiting a head state.
    pub fn fully_synced_peer_found(&mut self) {
        self.chains.fully_synced_peer_found()
    }

    pub fn add_peer(
        &mut self,
        network: &mut SyncNetworkContext,
        peer_id: PeerId,
        remote: PeerSyncInfo,
    ) {
        // evaluate which chain to sync from

        // determine if we need to run a sync to the nearest finalized state or simply sync to
        // its current head
        let local_info = match self.beacon_chain.upgrade() {
            Some(chain) => PeerSyncInfo::from(&chain),
            None => {
                warn!(self.log,
                      "Beacon chain dropped. Peer not considered for sync";
                      "peer_id" => format!("{:?}", peer_id));
                return;
            }
        };

        // convenience variables
        let remote_finalized_slot = remote
            .finalized_epoch
            .start_slot(T::EthSpec::slots_per_epoch());
        let local_finalized_slot = local_info
            .finalized_epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        // firstly, remove any out-of-date chains
        self.chains.purge_finalized(local_finalized_slot);
        self.chains.purge_head(local_info.head_slot);

        // remove peer from any chains
        self.remove_peer(network, &peer_id);

        if remote_finalized_slot > local_info.head_slot {
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
                chain.peer_pool.insert(peer_id.clone());
                chain.peer_added(network, peer_id, &self.log);

                // check if the new peer's addition will favour a new syncing chain.
                self.chains
                    .update_finalized(self.beacon_chain.clone(), network, &self.log);
            } else {
                // there is no finalized chain that matches this peer's last finalized target
                // create a new finalized chain
                debug!(self.log, "New finalized chain added to sync"; "peer_id" => format!("{:?}", peer_id), "start_slot" => local_finalized_slot.as_u64(), "end_slot" => remote_finalized_slot.as_u64(), "finalized_root" => format!("{}", remote.finalized_root));

                self.chains.new_finalized_chain(
                    local_finalized_slot,
                    remote.finalized_root,
                    remote_finalized_slot,
                    peer_id,
                );
                self.chains
                    .update_finalized(self.beacon_chain.clone(), network, &self.log);
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
                chain.peer_pool.insert(peer_id.clone());
                chain.peer_added(network, peer_id.clone(), &self.log);
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
                    &self.log,
                );
            }
            self.chains
                .update_finalized(self.beacon_chain.clone(), network, &self.log);
        }
    }

    pub fn blocks_by_range_response(
        &mut self,
        network: &mut SyncNetworkContext,
        peer_id: PeerId,
        request_id: RequestId,
        beacon_block: Option<BeaconBlock<T::EthSpec>>,
    ) {
        // Find the request. Most likely the first finalized chain (the syncing chain). If there
        // are no finalized chains, then it will be a head chain. At most, there should only be
        // `connected_peers` number of head chains, which should be relatively small and this
        // lookup should not be very expensive. However, we could add an extra index that maps the
        // request id to index of the vector to avoid O(N) searches and O(N) hash lookups.
        // Note to future sync-rewriter/profiler: Michael approves of these O(N) searches.

        let chain_ref = &self.beacon_chain;
        let log_ref = &self.log;
        match self.chains.finalized_request(|chain| {
            chain.on_block_response(chain_ref, network, request_id, &beacon_block, log_ref)
        }) {
            Some((_, ProcessingResult::KeepChain)) => {} // blocks added to the chain
            Some((index, ProcessingResult::RemoveChain)) => {
                let chain = self.chains.remove_finalized_chain(index);
                debug!(self.log, "Finalized chain removed"; "start_slot" => chain.start_slot.as_u64(), "end_slot" => chain.target_head_slot.as_u64());
                // the chain is complete, re-status it's peers
                chain.status_peers(self.beacon_chain.clone(), network);

                // update the state of the collection
                self.chains
                    .update_finalized(self.beacon_chain.clone(), network, &self.log);

                // set the state to a head sync, to inform the manager that we are awaiting a
                // head chain.
                self.chains.set_head_sync();

                // if there are no more finalized chains, re-status all known peers awaiting a head
                // sync
                match self.chains.sync_state() {
                    SyncState::Idle | SyncState::Head => {
                        for peer_id in self.awaiting_head_peers.iter() {
                            network.status_peer(self.beacon_chain.clone(), peer_id.clone());
                        }
                    }
                    SyncState::Finalized => {} // Have more finalized chains to complete
                }
            }
            None => {
                // The request was not in any finalized chain, search head chains
                match self.chains.head_request(|chain| {
                    chain.on_block_response(&chain_ref, network, request_id, &beacon_block, log_ref)
                }) {
                    Some((index, ProcessingResult::RemoveChain)) => {
                        let chain = self.chains.remove_head_chain(index);
                        debug!(self.log, "Head chain completed"; "start_slot" => chain.start_slot.as_u64(), "end_slot" => chain.target_head_slot.as_u64());
                        // the chain is complete, re-status it's peers and remove it
                        chain.status_peers(self.beacon_chain.clone(), network);

                        // update the state of the collection
                        self.chains
                            .update_finalized(self.beacon_chain.clone(), network, &self.log);
                    }
                    Some(_) => {}
                    None => {
                        // The request didn't exist in any `SyncingChain`. Could have been an old request. Log
                        // and ignore
                        debug!(self.log, "Range response without matching request"; "peer" => format!("{:?}", peer_id), "request_id" => request_id);
                    }
                }
            }
        }
    }

    pub fn is_syncing(&self) -> bool {
        match self.chains.sync_state() {
            SyncState::Finalized => true,
            SyncState::Head => true,
            SyncState::Idle => false,
        }
    }

    pub fn peer_disconnect(&mut self, network: &mut SyncNetworkContext, peer_id: &PeerId) {
        // if the peer is in the awaiting head mapping, remove it
        self.awaiting_head_peers.remove(&peer_id);

        // remove the peer from any peer pool
        self.remove_peer(network, peer_id);

        // update the state of the collection
        self.chains
            .update_finalized(self.beacon_chain.clone(), network, &self.log);
    }

    /// When a peer gets removed, both the head and finalized chains need to be searched to check which pool the peer is in. The chain may also have a batch or batches awaiting
    /// for this peer. If so we mark the batch as failed. The batch may then hit it's maximum
    /// retries. In this case, we need to remove the chain and re-status all the peers.
    fn remove_peer(&mut self, network: &mut SyncNetworkContext, peer_id: &PeerId) {
        match self.chains.head_finalized_request(|chain| {
            if chain.peer_pool.remove(&peer_id) {
                // this chain contained the peer
                let pending_batches_requests = chain
                    .pending_batches
                    .iter()
                    .filter(|(_, batch)| batch.current_peer == *peer_id)
                    .map(|(id, _)| id)
                    .cloned()
                    .collect::<Vec<_>>();
                for request_id in pending_batches_requests {
                    if let Some(batch) = chain.pending_batches.remove(&request_id) {
                        if let ProcessingResult::RemoveChain = chain.failed_batch(network, batch) {
                            // a single batch failed, remove the chain
                            return Some(ProcessingResult::RemoveChain);
                        }
                    }
                }
                // peer removed from chain, no batch failed
                Some(ProcessingResult::KeepChain)
            } else {
                None
            }
        }) {
            Some((index, ProcessingResult::RemoveChain)) => {
                // the chain needed to be removed
                let chain = self.chains.remove_chain(index);
                debug!(self.log, "Chain was removed due batch failing"; "start_slot" => chain.start_slot.as_u64(), "end_slot" => chain.target_head_slot.as_u64());
                // the chain has been removed, re-status it's peers
                chain.status_peers(self.beacon_chain.clone(), network);
                // update the state of the collection
                self.chains
                    .update_finalized(self.beacon_chain.clone(), network, &self.log);
            }
            _ => {} // chain didn't need to be removed, ignore
        }

        // remove any chains that no longer have any peers
    }

    // An RPC Error occurred, if it's a pending batch, re-request it if possible, if there have
    // been too many attempts, remove the chain
    pub fn inject_error(
        &mut self,
        network: &mut SyncNetworkContext,
        peer_id: PeerId,
        request_id: RequestId,
    ) {
        // check that this request is pending
        let log_ref = &self.log;
        match self.chains.head_finalized_request(|chain| {
            chain.inject_error(network, &peer_id, &request_id, log_ref)
        }) {
            Some((_, ProcessingResult::KeepChain)) => {} // error handled chain persists
            Some((index, ProcessingResult::RemoveChain)) => {
                let chain = self.chains.remove_chain(index);
                debug!(self.log, "Chain was removed due to error"; "start_slot" => chain.start_slot.as_u64(), "end_slot" => chain.target_head_slot.as_u64());
                // the chain has failed, re-status it's peers
                chain.status_peers(self.beacon_chain.clone(), network);
                // update the state of the collection
                self.chains
                    .update_finalized(self.beacon_chain.clone(), network, &self.log);
            }
            None => {} // request wasn't in the finalized chains, check the head chains
        }
    }
}
