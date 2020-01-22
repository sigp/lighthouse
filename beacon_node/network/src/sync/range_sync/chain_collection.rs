//! This provides the logic for the finalized and head chains.
//!
//! Each chain type is stored in it's own vector. A variety of helper functions are given along
//! with this struct to to simplify the logic of the other layers of sync.

use super::chain::{ChainSyncingState, SyncingChain};
use crate::message_processor::PeerSyncInfo;
use crate::sync::manager::SyncMessage;
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::PeerId;
use slog::{debug, error, warn};
use std::sync::Weak;
use tokio::sync::mpsc;
use types::EthSpec;
use types::{Hash256, Slot};

/// The state of the long range/batch sync.
pub enum SyncState {
    /// A finalized chain is being synced.
    Finalized,
    /// There are no finalized chains and we are syncing one more head chains.
    Head,
    /// There are no head or finalized chains and no long range sync is in progress.
    Idle,
}

/// A collection of finalized and head chains currently being processed.
pub struct ChainCollection<T: BeaconChainTypes> {
    /// The beacon chain for processing.
    beacon_chain: Weak<BeaconChain<T>>,
    /// The set of finalized chains being synced.
    finalized_chains: Vec<SyncingChain<T>>,
    /// The set of head chains being synced.
    head_chains: Vec<SyncingChain<T>>,
    /// The current sync state of the process.
    sync_state: SyncState,
}

impl<T: BeaconChainTypes> ChainCollection<T> {
    pub fn new(beacon_chain: Weak<BeaconChain<T>>) -> Self {
        ChainCollection {
            sync_state: SyncState::Idle,
            finalized_chains: Vec::new(),
            head_chains: Vec::new(),
            beacon_chain,
        }
    }

    /// The current syncing state.
    pub fn sync_state(&self) -> &SyncState {
        &self.sync_state
    }

    /// A fully synced peer has joined.
    ///
    /// We could be awaiting a head sync. If we are in the head syncing state, without any head
    /// chains, then update the state to idle.
    pub fn fully_synced_peer_found(&mut self) {
        if let SyncState::Head = self.sync_state {
            if self.head_chains.is_empty() {
                self.sync_state = SyncState::Idle;
            }
        }
    }

    /// After a finalized chain completes this function is called. It ensures the state is set to
    /// `SyncState::Head` indicating we are awaiting new peers to connect before we can consider
    /// the state as idle.
    pub fn set_head_sync(&mut self) {
        if let SyncState::Idle = self.sync_state {
            self.sync_state = SyncState::Head;
        }
    }

    /// Finds any finalized chain if it exists.
    pub fn get_finalized_mut(
        &mut self,
        target_head_root: Hash256,
        target_head_slot: Slot,
    ) -> Option<&mut SyncingChain<T>> {
        ChainCollection::get_chain(
            self.finalized_chains.as_mut(),
            target_head_root,
            target_head_slot,
        )
    }

    /// Finds any finalized chain if it exists.
    pub fn get_head_mut(
        &mut self,
        target_head_root: Hash256,
        target_head_slot: Slot,
    ) -> Option<&mut SyncingChain<T>> {
        ChainCollection::get_chain(
            self.head_chains.as_mut(),
            target_head_root,
            target_head_slot,
        )
    }

    /// Updates the state of the chain collection.
    ///
    /// This removes any out-dated chains, swaps to any higher priority finalized chains and
    /// updates the state of the collection.
    pub fn update_finalized(&mut self, network: &mut SyncNetworkContext, log: &slog::Logger) {
        let local_slot = match self.beacon_chain.upgrade() {
            Some(chain) => {
                let local = match PeerSyncInfo::from_chain(&chain) {
                    Some(local) => local,
                    None => {
                        return error!(
                            log,
                            "Failed to get peer sync info";
                            "msg" => "likely due to head lock contention"
                        )
                    }
                };

                local
                    .finalized_epoch
                    .start_slot(T::EthSpec::slots_per_epoch())
            }
            None => {
                warn!(log, "Beacon chain dropped. Chains not updated");
                return;
            }
        };

        // Remove any outdated finalized chains
        self.purge_outdated_chains(network, log);

        // Check if any chains become the new syncing chain
        if let Some(index) = self.finalized_syncing_index() {
            // There is a current finalized chain syncing
            let syncing_chain_peer_count = self.finalized_chains[index].peer_pool.len();

            // search for a chain with more peers
            if let Some((new_index, chain)) =
                self.finalized_chains
                    .iter_mut()
                    .enumerate()
                    .find(|(iter_index, chain)| {
                        *iter_index != index && chain.peer_pool.len() > syncing_chain_peer_count
                    })
            {
                // A chain has more peers. Swap the syncing chain
                debug!(log, "Switching finalized chains to sync"; "new_target_root" => format!("{}", chain.target_head_root), "new_end_slot" => chain.target_head_slot, "new_start_slot"=> chain.start_slot);

                // Stop the current chain from syncing
                self.finalized_chains[index].stop_syncing();
                // Start the new chain
                self.finalized_chains[new_index].start_syncing(network, local_slot);
                self.sync_state = SyncState::Finalized;
            }
        } else if let Some(chain) = self
            .finalized_chains
            .iter_mut()
            .max_by_key(|chain| chain.peer_pool.len())
        {
            // There is no currently syncing finalization chain, starting the one with the most peers
            debug!(log, "New finalized chain started syncing"; "new_target_root" => format!("{}", chain.target_head_root), "new_end_slot" => chain.target_head_slot, "new_start_slot"=> chain.start_slot);
            chain.start_syncing(network, local_slot);
            self.sync_state = SyncState::Finalized;
        } else {
            // There are no finalized chains, update the state.
            if self.head_chains.is_empty() {
                self.sync_state = SyncState::Idle;
            } else {
                self.sync_state = SyncState::Head;
            }
        }
    }

    /// Add a new finalized chain to the collection.
    pub fn new_finalized_chain(
        &mut self,
        local_finalized_slot: Slot,
        target_head: Hash256,
        target_slot: Slot,
        peer_id: PeerId,
        sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
        log: &slog::Logger,
    ) {
        self.finalized_chains.push(SyncingChain::new(
            local_finalized_slot,
            target_slot,
            target_head,
            peer_id,
            sync_send,
            self.beacon_chain.clone(),
            log.clone(),
        ));
    }

    /// Add a new finalized chain to the collection and starts syncing it.
    #[allow(clippy::too_many_arguments)]
    pub fn new_head_chain(
        &mut self,
        network: &mut SyncNetworkContext,
        remote_finalized_slot: Slot,
        target_head: Hash256,
        target_slot: Slot,
        peer_id: PeerId,
        sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
        log: &slog::Logger,
    ) {
        // remove the peer from any other head chains

        self.head_chains.iter_mut().for_each(|chain| {
            chain.peer_pool.remove(&peer_id);
        });
        self.head_chains.retain(|chain| !chain.peer_pool.is_empty());

        let mut new_head_chain = SyncingChain::new(
            remote_finalized_slot,
            target_slot,
            target_head,
            peer_id,
            sync_send,
            self.beacon_chain.clone(),
            log.clone(),
        );
        // All head chains can sync simultaneously
        new_head_chain.start_syncing(network, remote_finalized_slot);
        self.head_chains.push(new_head_chain);
    }

    /// Returns if `true` if any finalized chains exist, `false` otherwise.
    pub fn is_finalizing_sync(&self) -> bool {
        !self.finalized_chains.is_empty()
    }

    /// Given a chain iterator, runs a given function on each chain until the function returns
    /// `Some`. This allows the `RangeSync` struct to loop over chains and optionally remove the
    /// chain from the collection if the function results in completing the chain.
    fn request_function<'a, F, I, U>(chain: I, mut func: F) -> Option<(usize, U)>
    where
        I: Iterator<Item = &'a mut SyncingChain<T>>,
        F: FnMut(&'a mut SyncingChain<T>) -> Option<U>,
    {
        chain
            .enumerate()
            .find_map(|(index, chain)| Some((index, func(chain)?)))
    }

    /// Runs a function on all finalized chains.
    pub fn finalized_request<F, U>(&mut self, func: F) -> Option<(usize, U)>
    where
        F: FnMut(&mut SyncingChain<T>) -> Option<U>,
    {
        ChainCollection::request_function(self.finalized_chains.iter_mut(), func)
    }

    /// Runs a function on all head chains.
    pub fn head_request<F, U>(&mut self, func: F) -> Option<(usize, U)>
    where
        F: FnMut(&mut SyncingChain<T>) -> Option<U>,
    {
        ChainCollection::request_function(self.head_chains.iter_mut(), func)
    }

    /// Runs a function on all finalized and head chains.
    pub fn head_finalized_request<F, U>(&mut self, func: F) -> Option<(usize, U)>
    where
        F: FnMut(&mut SyncingChain<T>) -> Option<U>,
    {
        ChainCollection::request_function(
            self.finalized_chains
                .iter_mut()
                .chain(self.head_chains.iter_mut()),
            func,
        )
    }

    /// Removes any outdated finalized or head chains.
    ///
    /// This removes chains with no peers, or chains whose start block slot is less than our current
    /// finalized block slot.
    pub fn purge_outdated_chains(&mut self, network: &mut SyncNetworkContext, log: &slog::Logger) {
        // Remove any chains that have no peers
        self.finalized_chains
            .retain(|chain| !chain.peer_pool.is_empty());
        self.head_chains.retain(|chain| !chain.peer_pool.is_empty());

        let (beacon_chain, local_info) = match self.beacon_chain.upgrade() {
            Some(chain) => match PeerSyncInfo::from_chain(&chain) {
                Some(local) => (chain, local),
                None => {
                    return error!(
                        log,
                        "Failed to get peer sync info";
                        "msg" => "likely due to head lock contention"
                    )
                }
            },
            None => {
                return;
            }
        };

        let local_finalized_slot = local_info
            .finalized_epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        // Remove chains that are out-dated and re-status their peers
        self.finalized_chains.retain(|chain| {
            if chain.target_head_slot <= local_finalized_slot
                || beacon_chain
                    .block_root_tree
                    .is_known_block_root(&chain.target_head_root)
            {
                chain.status_peers(network);
                false
            } else {
                true
            }
        });
        self.head_chains.retain(|chain| {
            if chain.target_head_slot <= local_finalized_slot
                || beacon_chain
                    .block_root_tree
                    .is_known_block_root(&chain.target_head_root)
            {
                chain.status_peers(network);
                false
            } else {
                true
            }
        });
    }

    /// Removes and returns a finalized chain from the collection.
    pub fn remove_finalized_chain(&mut self, index: usize) -> SyncingChain<T> {
        self.finalized_chains.swap_remove(index)
    }

    /// Removes and returns a head chain from the collection.
    pub fn remove_head_chain(&mut self, index: usize) -> SyncingChain<T> {
        self.head_chains.swap_remove(index)
    }

    /// Removes a chain from either finalized or head chains based on the index. Using a request
    /// iterates of finalized chains before head chains. Thus an index that is greater than the
    /// finalized chain length, indicates a head chain.
    ///
    /// This will re-status the chains peers on removal. The index must exist.
    pub fn remove_chain(
        &mut self,
        network: &mut SyncNetworkContext,
        index: usize,
        log: &slog::Logger,
    ) {
        let chain = if index >= self.finalized_chains.len() {
            let index = index - self.finalized_chains.len();
            let chain = self.head_chains.swap_remove(index);
            chain.status_peers(network);
            chain
        } else {
            let chain = self.finalized_chains.swap_remove(index);
            chain.status_peers(network);
            chain
        };

        debug!(log, "Chain was removed"; "start_slot" => chain.start_slot.as_u64(), "end_slot" => chain.target_head_slot.as_u64());

        // update the state
        self.update_finalized(network, log);
    }

    /// Returns the index of finalized chain that is currently syncing. Returns `None` if no
    /// finalized chain is currently syncing.
    fn finalized_syncing_index(&self) -> Option<usize> {
        self.finalized_chains
            .iter()
            .enumerate()
            .find_map(|(index, chain)| {
                if chain.state == ChainSyncingState::Syncing {
                    Some(index)
                } else {
                    None
                }
            })
    }

    /// Returns a chain given the target head root and slot.
    fn get_chain<'a>(
        chain: &'a mut [SyncingChain<T>],
        target_head_root: Hash256,
        target_head_slot: Slot,
    ) -> Option<&'a mut SyncingChain<T>> {
        chain.iter_mut().find(|iter_chain| {
            iter_chain.target_head_root == target_head_root
                && iter_chain.target_head_slot == target_head_slot
        })
    }
}
