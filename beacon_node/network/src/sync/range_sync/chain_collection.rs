//! This provides the logic for the finalized and head chains.
//!
//! Each chain type is stored in it's own vector. A variety of helper functions are given along
//! with this struct to to simplify the logic of the other layers of sync.

use super::chain::{ChainSyncingState, SyncingChain};
use crate::beacon_processor::WorkEvent as BeaconWorkEvent;
use crate::sync::network_context::SyncNetworkContext;
use crate::sync::PeerSyncInfo;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::{types::SyncState, NetworkGlobals, PeerId};
use slog::{debug, error, info, o};
use std::sync::Arc;
use tokio::sync::mpsc;
use types::EthSpec;
use types::{Epoch, Hash256, Slot};

/// The number of head syncing chains to sync at a time.
const PARALLEL_HEAD_CHAINS: usize = 2;

/// The state of the long range/batch sync.
#[derive(Clone)]
pub enum RangeSyncState {
    /// A finalized chain is being synced.
    Finalized {
        /// The start of the finalized chain.
        start_slot: Slot,
        /// The target head slot of the finalized chain.
        head_slot: Slot,
        /// The target head root of the finalized chain.
        head_root: Hash256,
    },
    /// There are no finalized chains and we are syncing one more head chains.
    Head {
        /// The last finalized checkpoint for all head chains.
        start_slot: Slot,
        /// The largest known slot to sync to.
        head_slot: Slot,
    },
    /// There are no head or finalized chains and no long range sync is in progress.
    Idle,
}

impl PartialEq for RangeSyncState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (RangeSyncState::Finalized { .. }, RangeSyncState::Finalized { .. }) => true,
            (RangeSyncState::Head { .. }, RangeSyncState::Head { .. }) => true,
            (RangeSyncState::Idle, RangeSyncState::Idle) => true,
            _ => false,
        }
    }
}

impl Into<SyncState> for RangeSyncState {
    fn into(self) -> SyncState {
        match self {
            RangeSyncState::Finalized {
                start_slot,
                head_slot,
                head_root,
            } => SyncState::SyncingFinalized {
                start_slot,
                head_slot,
                head_root,
            },
            RangeSyncState::Head {
                start_slot,
                head_slot,
            } => SyncState::SyncingHead {
                start_slot,
                head_slot,
            },
            RangeSyncState::Idle => SyncState::Stalled, // this should never really be used
        }
    }
}

/// A collection of finalized and head chains currently being processed.
pub struct ChainCollection<T: BeaconChainTypes> {
    /// The beacon chain for processing.
    beacon_chain: Arc<BeaconChain<T>>,
    /// A reference to the global network parameters.
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    /// The set of finalized chains being synced.
    finalized_chains: Vec<SyncingChain<T>>,
    /// The set of head chains being synced.
    head_chains: Vec<SyncingChain<T>>,
    /// The current sync state of the process.
    state: RangeSyncState,
    /// Logger for the collection.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> ChainCollection<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        log: slog::Logger,
    ) -> Self {
        ChainCollection {
            beacon_chain,
            network_globals,
            finalized_chains: Vec::new(),
            head_chains: Vec::new(),
            state: RangeSyncState::Idle,
            log,
        }
    }

    pub fn state(&self) -> &RangeSyncState {
        &self.state
    }

    /// Updates the global sync state and logs any changes.
    pub fn update_sync_state(&mut self, network: &mut SyncNetworkContext<T::EthSpec>) {
        // if there is no range sync occurring, the state is either synced or not based on
        // connected peers.

        if self.state == RangeSyncState::Idle {
            // there is no range sync, let the state of peers determine the global node sync state
            let new_state = self
                .network_globals
                .peers
                .read()
                .synced_peers()
                .next()
                .map(|_| SyncState::Synced)
                .unwrap_or_else(|| SyncState::Stalled);
            let mut peer_state = self.network_globals.sync_state.write();
            if new_state != *peer_state {
                info!(self.log, "Sync state updated"; "old_state" => format!("{}",peer_state), "new_state" => format!("{}",new_state));
                if new_state == SyncState::Synced {
                    network.subscribe_core_topics();
                }
                *peer_state = new_state;
            }
        } else {
            // The state is based on a range sync state, update it
            let mut node_sync_state = self.network_globals.sync_state.write();
            let new_state: SyncState = self.state.clone().into();
            if *node_sync_state != new_state {
                // we are updating the state, inform the user
                info!(self.log, "Sync state updated"; "old_state" => format!("{}",node_sync_state), "new_state" => format!("{}",new_state));
            }
            *node_sync_state = new_state;
        }
    }

    /// A fully synced peer has joined.
    ///
    /// We could be awaiting a head sync. If we are in the head syncing state, without any head
    /// chains, then update the state to idle.
    pub fn fully_synced_peer_found(&mut self, network: &mut SyncNetworkContext<T::EthSpec>) {
        if let RangeSyncState::Head { .. } = self.state {
            if self.head_chains.is_empty() {
                // Update the global network state to either synced or stalled.
                self.state = RangeSyncState::Idle;
                self.update_sync_state(network);
            }
        }
    }

    /// After a finalized chain completes this function is called. It ensures the state is set to
    /// `SyncState::Head` indicating we are awaiting new peers to connect before we can consider
    /// the state as idle.
    pub fn set_head_sync(&mut self) {
        if let RangeSyncState::Idle = self.state {
            let current_slot = self
                .beacon_chain
                .head_info()
                .map(|info| info.slot)
                .unwrap_or_else(|_| Slot::from(0u64));

            // NOTE: This will modify the /node/syncing API to show current slot for all fields
            // while we update peers to look for new potentially HEAD chains.
            let temp_head_state = RangeSyncState::Head {
                start_slot: current_slot,
                head_slot: current_slot,
            };
            self.state = temp_head_state;
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
    /// updates the state of the collection. This starts head chains syncing if any are required to
    /// do so.
    pub fn update(&mut self, network: &mut SyncNetworkContext<T::EthSpec>) {
        let local_epoch = {
            let local = match PeerSyncInfo::from_chain(&self.beacon_chain) {
                Some(local) => local,
                None => {
                    return error!(
                        self.log,
                        "Failed to get peer sync info";
                        "msg" => "likely due to head lock contention"
                    )
                }
            };

            local.finalized_epoch
        };

        // Remove any outdated finalized/head chains
        self.purge_outdated_chains(network);

        // Choose the best finalized chain if one needs to be selected.
        self.update_finalized_chains(network, local_epoch);

        if self.finalized_syncing_index().is_none() {
            // Handle head syncing chains if there are no finalized chains left.
            self.update_head_chains(network, local_epoch);
        }
    }

    /// This looks at all current finalized chains and decides if a new chain should be prioritised
    /// or not.
    fn update_finalized_chains(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        local_epoch: Epoch,
    ) {
        // Check if any chains become the new syncing chain
        if let Some(index) = self.finalized_syncing_index() {
            // There is a current finalized chain syncing
            let _syncing_chain_peer_count = self.finalized_chains[index].peer_pool.len();

            // search for a chain with more peers
            if let Some((new_index, chain)) =
                self.finalized_chains
                    .iter_mut()
                    .enumerate()
                    .find(|(_iter_index, _chain)| {
                        false
                        //    && *iter_index != index
                        //    && chain.peer_pool.len() > syncing_chain_peer_count
                    })
            {
                // A chain has more peers. Swap the syncing chain
                debug!(self.log, "Switching finalized chains to sync"; "new_target_root" => format!("{}", chain.target_head_root), "new_end_slot" => chain.target_head_slot, "new_start_epoch"=> local_epoch);

                // update the state to a new finalized state
                let state = RangeSyncState::Finalized {
                    start_slot: chain.start_epoch.start_slot(T::EthSpec::slots_per_epoch()),
                    head_slot: chain.target_head_slot,
                    head_root: chain.target_head_root,
                };
                self.state = state;

                // Stop the current chain from syncing
                self.finalized_chains[index].stop_syncing();
                // Start the new chain
                self.finalized_chains[new_index].start_syncing(network, local_epoch);
            }
        } else if let Some(chain) = self
            .finalized_chains
            .iter_mut()
            .max_by_key(|chain| chain.peer_pool.len())
        {
            // There is no currently syncing finalization chain, starting the one with the most peers
            debug!(self.log, "New finalized chain started syncing"; "new_target_root" => format!("{}", chain.target_head_root), "new_end_slot" => chain.target_head_slot, "new_start_epoch"=> chain.start_epoch);
            chain.start_syncing(network, local_epoch);
            let state = RangeSyncState::Finalized {
                start_slot: chain.start_epoch.start_slot(T::EthSpec::slots_per_epoch()),
                head_slot: chain.target_head_slot,
                head_root: chain.target_head_root,
            };
            self.state = state;
        }
    }

    /// Start syncing any head chains if required.
    fn update_head_chains(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        local_epoch: Epoch,
    ) {
        // There are no finalized chains, update the state.
        if self.head_chains.is_empty() {
            self.state = RangeSyncState::Idle;
            return;
        }

        let mut currently_syncing = self
            .head_chains
            .iter()
            .filter(|chain| chain.is_syncing())
            .count();
        let mut not_syncing = self.head_chains.len() - currently_syncing;

        // Find all head chains that are not currently syncing ordered by peer count.
        while currently_syncing <= PARALLEL_HEAD_CHAINS && not_syncing > 0 {
            // Find the chain with the most peers and start syncing
            if let Some((_index, chain)) = self
                .head_chains
                .iter_mut()
                .filter(|chain| !chain.is_syncing())
                .enumerate()
                .max_by_key(|(_index, chain)| chain.peer_pool.len())
            {
                // start syncing this chain
                debug!(self.log, "New head chain started syncing"; "new_target_root" => format!("{}", chain.target_head_root), "new_end_slot" => chain.target_head_slot, "new_start_epoch"=> chain.start_epoch);
                chain.start_syncing(network, local_epoch);
            }

            // update variables
            currently_syncing = self
                .head_chains
                .iter()
                .filter(|chain| chain.is_syncing())
                .count();
            not_syncing = self.head_chains.len() - currently_syncing;
        }

        // Start
        // for the syncing API, we find the minimal start_slot and the maximum
        // target_slot of all head chains to report back.

        let (min_epoch, max_slot) = self
            .head_chains
            .iter()
            .filter(|chain| chain.is_syncing())
            .fold(
                (Epoch::from(0u64), Slot::from(0u64)),
                |(min, max), chain| {
                    (
                        std::cmp::min(min, chain.start_epoch),
                        std::cmp::max(max, chain.target_head_slot),
                    )
                },
            );
        let head_state = RangeSyncState::Head {
            start_slot: min_epoch.start_slot(T::EthSpec::slots_per_epoch()),
            head_slot: max_slot,
        };
        self.state = head_state;
    }

    /// This is called once a head chain has completed syncing. It removes all non-syncing head
    /// chains and re-status their peers.
    pub fn clear_head_chains(&mut self, network: &mut SyncNetworkContext<T::EthSpec>) {
        let log_ref = &self.log;
        self.head_chains.retain(|chain| {
            if !chain.is_syncing()
                {
                debug!(log_ref, "Removing old head chain"; "start_epoch" => chain.start_epoch, "end_slot" => chain.target_head_slot);
                chain.status_peers(network);
                false
            } else {
                true
            }
        });
    }

    /// Add a new finalized chain to the collection.
    pub fn new_finalized_chain(
        &mut self,
        local_finalized_epoch: Epoch,
        target_head: Hash256,
        target_slot: Slot,
        peer_id: PeerId,
        beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T::EthSpec>>,
    ) {
        let chain_id = rand::random();
        self.finalized_chains.push(SyncingChain::new(
            chain_id,
            local_finalized_epoch,
            target_slot,
            target_head,
            peer_id,
            beacon_processor_send,
            self.beacon_chain.clone(),
            self.log.new(o!("chain" => chain_id)),
        ));
    }

    /// Add a new finalized chain to the collection and starts syncing it.
    #[allow(clippy::too_many_arguments)]
    pub fn new_head_chain(
        &mut self,
        remote_finalized_epoch: Epoch,
        target_head: Hash256,
        target_slot: Slot,
        peer_id: PeerId,
        beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T::EthSpec>>,
    ) {
        // remove the peer from any other head chains

        self.head_chains.iter_mut().for_each(|chain| {
            chain.peer_pool.remove(&peer_id);
        });
        self.head_chains.retain(|chain| !chain.peer_pool.is_empty());

        let chain_id = rand::random();
        let new_head_chain = SyncingChain::new(
            chain_id,
            remote_finalized_epoch,
            target_slot,
            target_head,
            peer_id,
            beacon_processor_send,
            self.beacon_chain.clone(),
            self.log.clone(),
        );
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

    /// Given a chain iterator, runs a given function on each chain and return all `Some` results.
    fn request_function_all<'a, F, I, U>(chain: I, mut func: F) -> Vec<(usize, U)>
    where
        I: Iterator<Item = &'a mut SyncingChain<T>>,
        F: FnMut(&'a mut SyncingChain<T>) -> Option<U>,
    {
        chain
            .enumerate()
            .filter_map(|(index, chain)| Some((index, func(chain)?)))
            .collect()
    }

    /// Runs a function on finalized chains until we get the first `Some` result from `F`.
    pub fn finalized_request<F, U>(&mut self, func: F) -> Option<(usize, U)>
    where
        F: FnMut(&mut SyncingChain<T>) -> Option<U>,
    {
        ChainCollection::request_function(self.finalized_chains.iter_mut(), func)
    }

    /// Runs a function on head chains until we get the first `Some` result from `F`.
    pub fn head_request<F, U>(&mut self, func: F) -> Option<(usize, U)>
    where
        F: FnMut(&mut SyncingChain<T>) -> Option<U>,
    {
        ChainCollection::request_function(self.head_chains.iter_mut(), func)
    }

    /// Runs a function on finalized and head chains until we get the first `Some` result from `F`.
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

    /// Runs a function on all finalized and head chains and collects all `Some` results from `F`.
    pub fn head_finalized_request_all<F, U>(&mut self, func: F) -> Vec<(usize, U)>
    where
        F: FnMut(&mut SyncingChain<T>) -> Option<U>,
    {
        ChainCollection::request_function_all(
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
    pub fn purge_outdated_chains(&mut self, network: &mut SyncNetworkContext<T::EthSpec>) {
        // Remove any chains that have no peers
        self.finalized_chains
            .retain(|chain| !chain.peer_pool.is_empty());
        self.head_chains.retain(|chain| !chain.peer_pool.is_empty());

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

        let local_finalized_slot = local_info
            .finalized_epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        let beacon_chain = &self.beacon_chain;
        let log_ref = &self.log;
        // Remove chains that are out-dated and re-status their peers
        self.finalized_chains.retain(|chain| {
            if chain.target_head_slot <= local_finalized_slot
                || beacon_chain
                    .fork_choice
                    .read()
                    .contains_block(&chain.target_head_root)
            {
                debug!(log_ref, "Purging out of finalized chain"; "start_epoch" => chain.start_epoch, "end_slot" => chain.target_head_slot);
                chain.status_peers(network);
                false
            } else {
                true
            }
        });
        self.head_chains.retain(|chain| {
            if chain.target_head_slot <= local_finalized_slot
                || beacon_chain
                    .fork_choice
                    .read()
                    .contains_block(&chain.target_head_root)
            {
                debug!(log_ref, "Purging out of date head chain"; "start_epoch" => chain.start_epoch, "end_slot" => chain.target_head_slot);
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
    pub fn remove_chain(&mut self, network: &mut SyncNetworkContext<T::EthSpec>, index: usize) {
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

        debug!(self.log, "Chain was removed"; "start_epoch" => chain.start_epoch, "end_slot" => chain.target_head_slot);

        // update the state
        self.update(network);
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
