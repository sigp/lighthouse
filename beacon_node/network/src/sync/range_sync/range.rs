use super::chain::{ProcessingResult, SyncingChain};
use crate::sync::message_processor::PeerSyncInfo;
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::rpc::RequestId;
use eth2_libp2p::PeerId;
use slog::{crit, debug, trace, warn};
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
    chain: Weak<BeaconChain<T>>,
    /// A network context that provides the ability to send RPC requests/responses and handles a
    /// global request id for the syncing thread.
    //    network: &'a mut SyncNetworkContext,
    /// The current state of the RangeSync
    state: SyncState,
    /// A collection of finalized chains that need to be downloaded.
    finalized_chains: Vec<SyncingChain<T>>,
    /// A collection of head chains that need to be downloaded.
    head_chains: Vec<SyncingChain<T>>,
    /// Known peers to the RangeSync, that need to be re-status'd once finalized chains are
    /// completed.
    awaiting_head_peers: HashSet<PeerId>,
    log: slog::Logger,
}

enum SyncState {
    Finalized,
    Head,
    Idle,
}

impl<T: BeaconChainTypes> RangeSync<T> {
    pub fn new(chain: Weak<BeaconChain<T>>, log: slog::Logger) -> Self {
        RangeSync {
            chain,
            state: SyncState::Idle,
            finalized_chains: Vec::new(),
            head_chains: Vec::new(),
            awaiting_head_peers: HashSet::new(),
            log,
        }
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
        let local_info = match self.chain.upgrade() {
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

        // firstly, remove any out of date chains
        self.finalized_chains
            .retain(|chain| chain.target_head_slot > local_finalized_slot);
        self.head_chains
            .retain(|chain| chain.target_head_slot > local_info.head_slot);

        if remote_finalized_slot > local_info.head_slot {
            debug!(self.log, "Beginning a finalization sync"; "peer_id" => format!("{:?}", peer_id));
            // finalized chain search

            // Note: We keep current head chains. These can continue syncing whilst we complete
            // this new finalized chain.

            // if a finalized chain already exists that matches, add this peer to the chain's peer
            // pool.
            if let Some(index) = self.finalized_chains.iter().position(|chain| {
                chain.target_head_root == remote.finalized_root
                    && chain.target_head_slot == remote_finalized_slot
            }) {
                {
                    let chain = &self.finalized_chains[index];
                    trace!(self.log, "Finalized chain exists, adding peer"; "peer_id" => format!("{:?}", peer_id), "target_root" => format!("{}", chain.target_head_root), "end_slot" => chain.target_head_slot, "start_slot"=> chain.start_slot);
                }
                // add the peer to the chain's peer pool
                self.finalized_chains[index]
                    .peer_pool
                    .insert(peer_id.clone());

                // check if the new peer's addition will favour a new syncing chain.
                if index != 0
                    && self.finalized_chains[index].peer_pool.len()
                        > self.finalized_chains[0].peer_pool.len()
                {
                    // switch to the new syncing chain and stop the old

                    self.finalized_chains[0].stop_syncing();
                    let new_best = self.finalized_chains.swap_remove(index);
                    trace!(self.log, "Switching finalized chains to sync"; "peer_id" => format!("{:?}", peer_id), "new_target_root" => format!("{}", new_best.target_head_root), "new_end_slot" => new_best.target_head_slot, "new_start_slot"=> new_best.start_slot);
                    self.finalized_chains.insert(0, new_best);
                    // start syncing the better chain
                    self.finalized_chains[0].start_syncing(
                        network,
                        local_finalized_slot,
                        &self.log,
                    );
                } else {
                    // no new chain to sync, peer has been added to current syncing chain.
                    // Inform it to request batches from the peer
                    debug!(self.log, "Peer added to chain pool"; "peer_id" => format!("{:?}", peer_id));
                    self.finalized_chains[0].peer_added(network, peer_id, &self.log);
                }
            } else {
                // there is no finalized chain that matches this peer's last finalized target
                // create a new finalized chain
                debug!(self.log, "New finalized chain added to sync"; "peer_id" => format!("{:?}", peer_id), "start_slot" => local_finalized_slot.as_u64(), "end_slot" => remote_finalized_slot.as_u64(), "finalized_root" => format!("{}", remote.finalized_root));
                self.finalized_chains.push(SyncingChain::new(
                    local_finalized_slot,
                    remote_finalized_slot,
                    remote.finalized_root,
                    peer_id,
                ));

                // This chain will only have a single peer, and will only become the syncing chain
                // if no other chain exists
                if self.finalized_chains.len() == 1 {
                    self.finalized_chains[0].start_syncing(
                        network,
                        local_finalized_slot,
                        &self.log,
                    );
                }
            };
            self.state = SyncState::Finalized;
        } else {
            if !self.finalized_chains.is_empty() {
                // If there are finalized chains to sync, finish these first, before syncing head
                // chains. This allows us to re-sync all known peers
                trace!(self.log, "Waiting for finalized sync to complete"; "peer_id" => format!("{:?}", peer_id));
                return;
            }

            // The new peer has the same finalized (earlier filters should prevent a peer with an
            // earlier finalized chain from reaching here).
            trace!(self.log, "New peer added for recent head sync"; "peer_id" => format!("{:?}", peer_id));

            // search if there is a matching head chain, then add the peer to the chain
            if let Some(index) = self.head_chains.iter().position(|chain| {
                chain.target_head_root == remote.head_root
                    && chain.target_head_slot == remote.head_slot
            }) {
                debug!(self.log, "Adding peer to the existing head chain peer pool"; "head_root" => format!("{}",remote.head_root), "head_slot" => remote.head_slot, "peer_id" => format!("{:?}", peer_id));

                // add the peer to the head's pool
                self.head_chains[index].peer_pool.insert(peer_id.clone());
                self.head_chains[index].peer_added(network, peer_id.clone(), &self.log);
            } else {
                // There are no other head chains that match this peer's status, create a new one, and
                // remove the peer from any old ones
                self.head_chains.iter_mut().for_each(|chain| {
                    chain.peer_pool.remove(&peer_id);
                });
                self.head_chains.retain(|chain| !chain.peer_pool.is_empty());

                debug!(self.log, "Creating a new syncing head chain"; "head_root" => format!("{}",remote.head_root), "head_slot" => remote.head_slot, "peer_id" => format!("{:?}", peer_id));

                let mut new_head_chain = SyncingChain::new(
                    local_finalized_slot,
                    remote.head_slot,
                    remote.head_root,
                    peer_id,
                );
                // All head chains can sync simultaneously
                new_head_chain.start_syncing(network, local_finalized_slot, &self.log);
                self.head_chains.push(new_head_chain);
                self.state = SyncState::Head;
            }
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

        let chain_ref = &self.chain;
        let log_ref = &self.log;
        match self
            .finalized_chains
            .iter_mut()
            .enumerate()
            .find_map(|(index, chain)| {
                Some((
                    index,
                    chain.on_block_response(
                        chain_ref,
                        network,
                        request_id,
                        &beacon_block,
                        log_ref,
                    )?,
                ))
            }) {
            Some((index, ProcessingResult::RemoveChain)) => {
                let chain = self.finalized_chains.swap_remove(index);
                debug!(self.log, "Finalized chain completed"; "start_slot" => chain.start_slot.as_u64(), "end_slot" => chain.target_head_slot.as_u64());
                // the chain is complete, re-status it's peers and remove it
                chain.status_peers(self.chain.clone(), network);

                // The current completed chain was the
                // syncing chain
                if index == 0 {
                    self.update_finalized_chains(network);
                }
            }
            Some(_) => {} // blocks added to the chain
            None => {
                match self
                    .head_chains
                    .iter_mut()
                    .enumerate()
                    .find_map(|(index, chain)| {
                        Some((
                            index,
                            chain.on_block_response(
                                &chain_ref,
                                network,
                                request_id,
                                &beacon_block,
                                log_ref,
                            )?,
                        ))
                    }) {
                    Some((index, ProcessingResult::RemoveChain)) => {
                        let chain = self.head_chains.swap_remove(index);
                        debug!(self.log, "Head chain completed"; "start_slot" => chain.start_slot.as_u64(), "end_slot" => chain.target_head_slot.as_u64());
                        // the chain is complete, re-status it's peers and remove it
                        chain.status_peers(self.chain.clone(), network);
                        // update the current state if necessary
                        if self.head_chains.is_empty() && self.finalized_chains.is_empty() {
                            self.state = SyncState::Idle;
                        }
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

    // The current finalizing chain has completed. Clean any remaining finalized chains, start
    // syncing a new finalized chain if one exists, otherwise prepare to start a head sync.
    fn update_finalized_chains(&mut self, network: &mut SyncNetworkContext) {
        debug!(self.log, "Finalized syncing chain completed");
        // remove any out-dated finalized chains, re statusing their peers.
        let local_info = match self.chain.upgrade() {
            Some(chain) => PeerSyncInfo::from(&chain),
            None => {
                warn!(self.log,
                          "Beacon chain dropped. Not starting a new sync chain";);
                return;
            }
        };
        let beacon_chain = self.chain.clone();
        self.finalized_chains.retain(|chain| {
            if chain.target_head_slot <= local_info.head_slot {
                chain.status_peers(beacon_chain.clone(), network);
                false
            } else {
                true
            }
        });

        // check if there is a new finalized_chain
        if let Some(index) = self
            .finalized_chains
            .iter()
            .enumerate()
            .max_by_key(|(_, chain)| chain.peer_pool.len())
            .map(|(index, _)| index)
        {
            // new syncing chain, begin syncing
            let new_chain = self.finalized_chains.swap_remove(index);
            self.finalized_chains.insert(0, new_chain);
            let local_finalized_slot = local_info
                .finalized_epoch
                .start_slot(T::EthSpec::slots_per_epoch());
            self.finalized_chains[0].start_syncing(network, local_finalized_slot, &self.log);
        } else {
            // there is no new finalized_chain, this was the last, re-status all head_peers to
            // begin a head sync if necessary
            for peer_id in self.awaiting_head_peers.iter() {
                network.status_peer(self.chain.clone(), peer_id.clone());
            }
            // change the status to idle, as head syncing may not be required
            self.state = if self.head_chains.is_empty() {
                SyncState::Idle
            } else {
                SyncState::Head
            };
        }
    }

    pub fn is_syncing(&self) -> bool {
        match self.state {
            SyncState::Finalized => true,
            SyncState::Head => true,
            SyncState::Idle => false,
        }
    }

    // If a peer disconnects, re-evaluate which chain to sync
    // TODO: Re-write this with a single head/finalized object
    pub fn peer_disconnect(&mut self, network: &mut SyncNetworkContext, peer_id: &PeerId) {
        self.awaiting_head_peers.remove(&peer_id);

        // remove the peer from any peer pool
        // in principle the peer should only exist in a single chain, for now, we will search all
        // chains and log a critical to ensure this is true.
        // TODO: Stop searching once a peer has been found and removed. - The ProcessingResult
        // pattern used elsewhere could then be applied.
        let mut peer_found = false;
        let mut chain_index_to_remove = None;

        for (index, chain) in self.finalized_chains.iter_mut().enumerate() {
            if chain.peer_pool.remove(&peer_id) {
                if peer_found {
                    crit!(self.log, "Peer existed in multiple chains");
                }
                peer_found = true;
            }
            //TODO: Remove this search once content the libp2p service instructs sync that a
            //pending request has been cancelled
            if chain
                .pending_batches
                .values()
                .find(|batch| batch.current_peer == *peer_id)
                .is_some()
            {
                crit!(
                    self.log,
                    "Sync was not alerted to a disconnected peer with ongoing request."
                );
            }

            if chain.peer_pool.is_empty() {
                chain_index_to_remove = Some(index);
            }
        }

        if let Some(index) = chain_index_to_remove {
            // the removed peer was the last in the chain. We remove the chain. If the chain was
            // currently syncing, search for a new chain to sync
            self.finalized_chains.remove(index);
            if index == 0 {
                self.update_finalized_chains(network);
            }
        }

        let mut chain_index_to_remove = None;
        // remove any peer for head chains
        for (index, chain) in self.head_chains.iter_mut().enumerate() {
            if chain.peer_pool.remove(&peer_id) {
                if peer_found {
                    crit!(self.log, "Peer existed in multiple chains");
                }
                peer_found = true;
            }
            //TODO: Remove this search once content the libp2p service instructs sync that a
            //pending request has been cancelled
            if chain
                .pending_batches
                .values()
                .find(|batch| batch.current_peer == *peer_id)
                .is_some()
            {
                crit!(
                    self.log,
                    "Sync was not alerted to a disconnected peer with ongoing request."
                );
            }

            if chain.peer_pool.is_empty() {
                chain_index_to_remove = Some(index);
            }
        }

        if let Some(index) = chain_index_to_remove {
            // the removed peer was the last in the chain. We remove the chain.
            self.head_chains.remove(index);

            // update the head state
            if self.head_chains.is_empty() && self.finalized_chains.is_empty() {
                self.state = SyncState::Idle;
            }
        }
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
        match self
            .finalized_chains
            .iter_mut()
            .enumerate()
            .find_map(|(index, chain)| {
                Some((
                    index,
                    chain.inject_error(network, &peer_id, &request_id, log_ref)?,
                ))
            }) {
            Some((_, ProcessingResult::KeepChain)) => {}
            Some((index, ProcessingResult::RemoveChain)) => {
                self.finalized_chains.remove(index);
                if index == 0 {
                    self.update_finalized_chains(network);
                }
            }
            None => {
                // request wasn't in the finalized chains, check the head chains
                match self
                    .head_chains
                    .iter_mut()
                    .enumerate()
                    .find_map(|(index, chain)| {
                        Some((
                            index,
                            chain.inject_error(network, &peer_id, &request_id, log_ref)?,
                        ))
                    }) {
                    Some((_, ProcessingResult::KeepChain)) => {}
                    Some((index, ProcessingResult::RemoveChain)) => {
                        self.finalized_chains.remove(index);
                    }
                    None => {} // request id was not recognized
                }
            }
        }
    }
}
