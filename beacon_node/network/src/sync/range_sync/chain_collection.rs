//! This provides the logic for the finalized and head chains.
//!
//! Each chain type is stored in it's own map. A variety of helper functions are given along with
//! this struct to simplify the logic of the other layers of sync.

use super::chain::{ChainId, ChainSyncingState, ProcessingResult, SyncingChain};
use super::sync_type::RangeSyncType;
use crate::beacon_processor::WorkEvent as BeaconWorkEvent;
use crate::sync::network_context::SyncNetworkContext;
use crate::sync::PeerSyncInfo;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::{types::SyncState, NetworkGlobals, PeerId};
use fnv::FnvHashMap;
use slog::{crit, debug, error, info, trace};
use std::collections::hash_map::Entry;
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
    finalized_chains: FnvHashMap<ChainId, SyncingChain<T>>,
    /// The set of head chains being synced.
    head_chains: FnvHashMap<ChainId, SyncingChain<T>>,
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
            finalized_chains: FnvHashMap::default(),
            head_chains: FnvHashMap::default(),
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
                info!(self.log, "Sync state updated"; "old_state" => %peer_state, "new_state" => %new_state);
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
                info!(self.log, "Sync state updated"; "old_state" => %node_sync_state, "new_state" => %new_state);
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

    /// Calls `func` on every chain of the collection. If the result is
    /// `ProcessingResult::RemoveChain`, the chain is removed and returned.
    pub fn call_all<F>(&mut self, mut func: F) -> Vec<(SyncingChain<T>, RangeSyncType)>
    where
        F: FnMut(&mut SyncingChain<T>) -> ProcessingResult,
    {
        let mut to_remove = Vec::new();

        for (id, chain) in self.finalized_chains.iter_mut() {
            if let ProcessingResult::RemoveChain = func(chain) {
                to_remove.push((*id, RangeSyncType::Finalized));
            }
        }

        for (id, chain) in self.head_chains.iter_mut() {
            if let ProcessingResult::RemoveChain = func(chain) {
                to_remove.push((*id, RangeSyncType::Head));
            }
        }

        let mut results = Vec::with_capacity(to_remove.len());
        for (id, sync_type) in to_remove.into_iter() {
            let chain = match sync_type {
                RangeSyncType::Finalized => self.finalized_chains.remove(&id),
                RangeSyncType::Head => self.head_chains.remove(&id),
            };
            results.push((chain.expect("Chain exits"), sync_type));
        }
        results
    }

    /// Executes a function on the chain with the given id.
    ///
    /// If the function returns `ProcessingResult::RemoveChain`, the chain is removed and returned.
    /// If the chain is found, its syncing type is returned, or an error otherwise.
    pub fn call_by_id<F>(
        &mut self,
        id: ChainId,
        func: F,
    ) -> Result<(Option<SyncingChain<T>>, RangeSyncType), ()>
    where
        F: FnOnce(&mut SyncingChain<T>) -> ProcessingResult,
    {
        if let Entry::Occupied(mut entry) = self.finalized_chains.entry(id) {
            // Search in our finalized chains first
            if let ProcessingResult::RemoveChain = func(entry.get_mut()) {
                Ok((Some(entry.remove()), RangeSyncType::Finalized))
            } else {
                Ok((None, RangeSyncType::Finalized))
            }
        } else if let Entry::Occupied(mut entry) = self.head_chains.entry(id) {
            // Search in our head chains next
            if let ProcessingResult::RemoveChain = func(entry.get_mut()) {
                Ok((Some(entry.remove()), RangeSyncType::Head))
            } else {
                Ok((None, RangeSyncType::Head))
            }
        } else {
            // Chain was not found in the finalized collection, nor the head collection
            Err(())
        }
    }

    /// Updates the state of the chain collection.
    ///
    /// This removes any out-dated chains, swaps to any higher priority finalized chains and
    /// updates the state of the collection. This starts head chains syncing if any are required to
    /// do so.
    pub fn update(&mut self, network: &mut SyncNetworkContext<T::EthSpec>) {
        let (local_finalized_epoch, local_head_epoch) =
            match PeerSyncInfo::from_chain(&self.beacon_chain) {
                None => {
                    return error!(
                        self.log,
                        "Failed to get peer sync info";
                        "msg" => "likely due to head lock contention"
                    )
                }
                Some(local) => (
                    local.finalized_epoch,
                    local.head_slot.epoch(T::EthSpec::slots_per_epoch()),
                ),
            };

        // Remove any outdated finalized/head chains
        self.purge_outdated_chains(network);

        // Choose the best finalized chain if one needs to be selected.
        self.update_finalized_chains(network, local_finalized_epoch, local_head_epoch);

        if self.finalized_syncing_chain().is_none() {
            // Handle head syncing chains if there are no finalized chains left.
            self.update_head_chains(network, local_finalized_epoch, local_head_epoch);
        }
    }

    /// This looks at all current finalized chains and decides if a new chain should be prioritised
    /// or not.
    fn update_finalized_chains(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        local_epoch: Epoch,
        local_head_epoch: Epoch,
    ) {
        // Find the chain with most peers and check if it is already syncing
        if let Some((new_id, peers)) = self
            .finalized_chains
            .iter()
            .max_by_key(|(_, chain)| chain.available_peers())
            .map(|(id, chain)| (*id, chain.available_peers()))
        {
            let old_id = self.finalized_syncing_chain().map(
                |(currently_syncing_id, currently_syncing_chain)| {
                    if *currently_syncing_id != new_id
                        && peers > currently_syncing_chain.available_peers()
                    {
                        currently_syncing_chain.stop_syncing();
                        // we stop this chain and start syncing the one with more peers
                        Some(*currently_syncing_id)
                    } else {
                        // the best chain is already the syncing chain, advance it if possible
                        None
                    }
                },
            );

            let chain = self
                .finalized_chains
                .get_mut(&new_id)
                .expect("Chain exists");

            match old_id {
                Some(Some(old_id)) => debug!(self.log, "Switching finalized chains";
                        "old_id" => old_id, &chain),
                None => debug!(self.log, "Syncing new chain"; &chain),
                Some(None) => trace!(self.log, "Advancing currently syncing chain"),
                // this is the same chain. We try to advance it.
            }
            // update the state to a new finalized state
            let state = RangeSyncState::Finalized {
                start_slot: chain.start_epoch.start_slot(T::EthSpec::slots_per_epoch()),
                head_slot: chain.target_head_slot,
                head_root: chain.target_head_root,
            };
            self.state = state;

            if let ProcessingResult::RemoveChain =
                chain.start_syncing(network, local_epoch, local_head_epoch)
            {
                // this happens only if sending a batch over the `network` fails a lot
                error!(self.log, "Chain removed while switching chains");
                self.finalized_chains.remove(&new_id);
            }
        }
    }

    /// Start syncing any head chains if required.
    fn update_head_chains(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        local_epoch: Epoch,
        local_head_epoch: Epoch,
    ) {
        // There are no finalized chains, update the state.
        if self.head_chains.is_empty() {
            self.state = RangeSyncState::Idle;
            return;
        }

        let mut currently_syncing = self
            .head_chains
            .values()
            .filter(|chain| chain.is_syncing())
            .count();
        let mut not_syncing = self.head_chains.len() - currently_syncing;
        // Find all head chains that are not currently syncing ordered by peer count.
        while currently_syncing <= PARALLEL_HEAD_CHAINS && not_syncing > 0 {
            // Find the chain with the most peers and start syncing
            if let Some((_id, chain)) = self
                .head_chains
                .iter_mut()
                .filter(|(_id, chain)| !chain.is_syncing())
                .max_by_key(|(_id, chain)| chain.available_peers())
            {
                // start syncing this chain
                debug!(self.log, "New head chain started syncing"; &chain);
                if let ProcessingResult::RemoveChain =
                    chain.start_syncing(network, local_epoch, local_head_epoch)
                {
                    error!(self.log, "Chain removed while switching head chains")
                }
            }
            // update variables
            currently_syncing = self
                .head_chains
                .iter()
                .filter(|(_id, chain)| chain.is_syncing())
                .count();
            not_syncing = self.head_chains.len() - currently_syncing;
        }
        // Start
        // for the syncing API, we find the minimal start_slot and the maximum
        // target_slot of all head chains to report back.
        let (min_epoch, max_slot) = self
            .head_chains
            .values()
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
        self.head_chains.retain(|_id, chain| {
            if !chain.is_syncing() {
                debug!(log_ref, "Removing old head chain"; &chain);
                chain.status_peers(network);
                false
            } else {
                true
            }
        });
    }

    /// Returns if `true` if any finalized chains exist, `false` otherwise.
    pub fn is_finalizing_sync(&self) -> bool {
        !self.finalized_chains.is_empty()
    }

    /// Removes any outdated finalized or head chains.
    /// This removes chains with no peers, or chains whose start block slot is less than our current
    /// finalized block slot.
    pub fn purge_outdated_chains(&mut self, network: &mut SyncNetworkContext<T::EthSpec>) {
        // Remove any chains that have no peers
        self.finalized_chains
            .retain(|_id, chain| chain.available_peers() > 0);
        self.head_chains
            .retain(|_id, chain| chain.available_peers() > 0);

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
        self.finalized_chains.retain(|_id, chain| {
            if chain.target_head_slot <= local_finalized_slot
                || beacon_chain
                    .fork_choice
                    .read()
                    .contains_block(&chain.target_head_root)
            {
                debug!(log_ref, "Purging out of finalized chain"; &chain);
                chain.status_peers(network);
                false
            } else {
                true
            }
        });
        self.head_chains.retain(|_id, chain| {
            if chain.target_head_slot <= local_finalized_slot
                || beacon_chain
                    .fork_choice
                    .read()
                    .contains_block(&chain.target_head_root)
            {
                debug!(log_ref, "Purging out of date head chain"; &chain);
                chain.status_peers(network);
                false
            } else {
                true
            }
        });
    }

    /// Adds a peer to a chain with the given target, or creates a new syncing chain if it doesn't
    /// exits.
    #[allow(clippy::too_many_arguments)]
    pub fn add_peer_or_create_chain(
        &mut self,
        start_epoch: Epoch,
        target_head_root: Hash256,
        target_head_slot: Slot,
        peer: PeerId,
        sync_type: RangeSyncType,
        beacon_processor_send: &mpsc::Sender<BeaconWorkEvent<T::EthSpec>>,
        network: &mut SyncNetworkContext<T::EthSpec>,
    ) {
        let id = SyncingChain::<T>::id(&target_head_root, &target_head_slot);
        let collection = if let RangeSyncType::Finalized = sync_type {
            if let Some(chain) = self.head_chains.get(&id) {
                // sanity verification for chain duplication / purging issues
                crit!(self.log, "Adding known head chain as finalized chain"; chain);
            }
            &mut self.finalized_chains
        } else {
            if let Some(chain) = self.finalized_chains.get(&id) {
                // sanity verification for chain duplication / purging issues
                crit!(self.log, "Adding known finalized chain as head chain"; chain);
            }
            &mut self.head_chains
        };
        match collection.entry(id) {
            Entry::Occupied(mut entry) => {
                let chain = entry.get_mut();
                debug!(self.log, "Adding peer to known chain"; "peer_id" => %peer, "sync_type" => ?sync_type, &chain);
                assert_eq!(chain.target_head_root, target_head_root);
                assert_eq!(chain.target_head_slot, target_head_slot);
                if let ProcessingResult::RemoveChain = chain.add_peer(network, peer) {
                    debug!(self.log, "Chain removed after adding peer"; "chain" => id);
                    entry.remove();
                }
            }
            Entry::Vacant(entry) => {
                let peer_rpr = peer.to_string();
                let new_chain = SyncingChain::new(
                    start_epoch,
                    target_head_slot,
                    target_head_root,
                    peer,
                    beacon_processor_send.clone(),
                    self.beacon_chain.clone(),
                    &self.log,
                );
                assert_eq!(new_chain.get_id(), id);
                debug!(self.log, "New chain added to sync"; "peer_id" => peer_rpr, "sync_type" => ?sync_type, &new_chain);
                entry.insert(new_chain);
            }
        }
    }

    /// Returns the index of finalized chain that is currently syncing. Returns `None` if no
    /// finalized chain is currently syncing.
    fn finalized_syncing_chain(&mut self) -> Option<(&ChainId, &mut SyncingChain<T>)> {
        self.finalized_chains.iter_mut().find_map(|(id, chain)| {
            if chain.state == ChainSyncingState::Syncing {
                Some((id, chain))
            } else {
                None
            }
        })
    }
}
