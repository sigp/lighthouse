use super::chain::{ChainSyncingState, ProcessingResult, SyncingChain};
use crate::message_processor::PeerSyncInfo;
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::PeerId;
use slog::{debug, warn};
use std::sync::Weak;
use types::EthSpec;
use types::{Hash256, Slot};

pub enum SyncState {
    Finalized,
    Head,
    Idle,
}
pub struct ChainCollection<T: BeaconChainTypes> {
    finalized_chains: Vec<SyncingChain<T>>,
    head_chains: Vec<SyncingChain<T>>,
    sync_state: SyncState,
}

impl<T: BeaconChainTypes> ChainCollection<T> {
    pub fn new() -> Self {
        ChainCollection {
            sync_state: SyncState::Idle,
            finalized_chains: Vec::new(),
            head_chains: Vec::new(),
        }
    }

    pub fn sync_state(&self) -> &SyncState {
        &self.sync_state
    }

    // if a finalized chain just completed, we assume we waiting for head syncing, unless a fully
    // sync peer joins.
    pub fn fully_synced_peer_found(&mut self) {
        if let SyncState::Head = self.sync_state {
            if self.head_chains.is_empty() {
                self.sync_state = SyncState::Idle;
            }
        }
    }

    // after a finalized chain completes, the state should be waiting for a head chain
    pub fn set_head_sync(&mut self) {
        if let SyncState::Idle = self.sync_state {
            self.sync_state = SyncState::Head;
        }
    }

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

    pub fn purge_finalized(&mut self, local_finalized_slot: Slot) {
        self.finalized_chains
            .retain(|chain| chain.target_head_slot > local_finalized_slot);
    }

    pub fn purge_head(&mut self, head_slot: Slot) {
        self.head_chains
            .retain(|chain| chain.target_head_slot > head_slot);
    }

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

    /// Checks if a new finalized state should become the syncing chain. Updates the state of the
    /// collection.
    pub fn update_finalized(
        &mut self,
        beacon_chain: Weak<BeaconChain<T>>,
        network: &mut SyncNetworkContext,
        log: &slog::Logger,
    ) {
        let local_info = match beacon_chain.upgrade() {
            Some(chain) => PeerSyncInfo::from(&chain),
            None => {
                warn!(log, "Beacon chain dropped. Chains not updated");
                return;
            }
        };

        let local_slot = local_info
            .finalized_epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        // Remove any outdated finalized chains
        self.purge_finalized(local_slot);
        self.finalized_chains
            .retain(|chain| !chain.peer_pool.is_empty());

        // Remove any outdated head chains
        self.purge_head(local_info.head_slot);
        self.finalized_chains
            .retain(|chain| !chain.peer_pool.is_empty());

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
                self.finalized_chains[new_index].start_syncing(network, local_slot, log);
                self.sync_state = SyncState::Finalized;
            }
        } else if let Some(chain) = self
            .finalized_chains
            .iter_mut()
            .max_by_key(|chain| chain.peer_pool.len())
        {
            // There is no currently syncing finalization chain, starting the one with the most peers
            debug!(log, "New finalized chain started syncing"; "new_target_root" => format!("{}", chain.target_head_root), "new_end_slot" => chain.target_head_slot, "new_start_slot"=> chain.start_slot);
            chain.start_syncing(network, local_slot, log);
            self.sync_state = SyncState::Finalized;
        } else {
            // There are no finalized chains, update the state
            if self.head_chains.is_empty() {
                self.sync_state = SyncState::Idle;
            } else {
                self.sync_state = SyncState::Head;
            }
        }
    }

    /// Add a new finalized chain to the collection
    pub fn new_finalized_chain(
        &mut self,
        local_finalized_slot: Slot,
        target_head: Hash256,
        target_slot: Slot,
        peer_id: PeerId,
    ) {
        self.finalized_chains.push(SyncingChain::new(
            local_finalized_slot,
            target_slot,
            target_head,
            peer_id,
        ));
    }

    /// Add a new finalized chain to the collection
    pub fn new_head_chain(
        &mut self,
        network: &mut SyncNetworkContext,
        remote_finalized_slot: Slot,
        target_head: Hash256,
        target_slot: Slot,
        peer_id: PeerId,
        log: &slog::Logger,
    ) {
        // remove the peer from any other head chains

        self.head_chains.iter_mut().for_each(|chain| {
            chain.peer_pool.remove(&peer_id);
        });
        self.head_chains.retain(|chain| !chain.peer_pool.is_empty());

        let mut new_head_chain =
            SyncingChain::new(remote_finalized_slot, target_slot, target_head, peer_id);
        // All head chains can sync simultaneously
        new_head_chain.start_syncing(network, remote_finalized_slot, log);
        self.head_chains.push(new_head_chain);
    }

    pub fn is_finalizing_sync(&self) -> bool {
        !self.finalized_chains.is_empty()
    }

    fn request_function<'a, F, I>(chain: I, mut func: F) -> Option<(usize, ProcessingResult)>
    where
        I: Iterator<Item = &'a mut SyncingChain<T>>,
        F: FnMut(&'a mut SyncingChain<T>) -> Option<ProcessingResult>,
    {
        chain
            .enumerate()
            .find_map(|(index, chain)| Some((index, func(chain)?)))
    }

    pub fn finalized_request<F>(&mut self, func: F) -> Option<(usize, ProcessingResult)>
    where
        F: FnMut(&mut SyncingChain<T>) -> Option<ProcessingResult>,
    {
        ChainCollection::request_function(self.finalized_chains.iter_mut(), func)
    }

    pub fn head_request<F>(&mut self, func: F) -> Option<(usize, ProcessingResult)>
    where
        F: FnMut(&mut SyncingChain<T>) -> Option<ProcessingResult>,
    {
        ChainCollection::request_function(self.head_chains.iter_mut(), func)
    }

    #[allow(dead_code)]
    pub fn head_finalized_request<F>(&mut self, func: F) -> Option<(usize, ProcessingResult)>
    where
        F: FnMut(&mut SyncingChain<T>) -> Option<ProcessingResult>,
    {
        ChainCollection::request_function(
            self.finalized_chains
                .iter_mut()
                .chain(self.head_chains.iter_mut()),
            func,
        )
    }

    pub fn remove_finalized_chain(&mut self, index: usize) -> SyncingChain<T> {
        self.finalized_chains.swap_remove(index)
    }

    pub fn remove_head_chain(&mut self, index: usize) -> SyncingChain<T> {
        self.head_chains.swap_remove(index)
    }

    /// Removes a chain from either finalized or head chains based on the index. Using a request
    /// iterates of finalized chains before head chains. Thus an index that is greater than the
    /// finalized chain length, indicates a head chain.
    pub fn remove_chain(&mut self, index: usize) -> SyncingChain<T> {
        if index >= self.finalized_chains.len() {
            let index = index - self.finalized_chains.len();
            self.head_chains.swap_remove(index)
        } else {
            self.finalized_chains.swap_remove(index)
        }
    }
}
