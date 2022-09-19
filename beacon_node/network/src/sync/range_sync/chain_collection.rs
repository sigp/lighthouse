//! This provides the logic for the finalized and head chains.
//!
//! Each chain type is stored in it's own map. A variety of helper functions are given along with
//! this struct to simplify the logic of the other layers of sync.

use super::block_storage::BlockStorage;
use super::chain::{ChainId, ProcessingResult, RemoveChain, SyncingChain};
use super::sync_type::RangeSyncType;
use crate::metrics;
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::BeaconChainTypes;
use fnv::FnvHashMap;
use lighthouse_network::PeerId;
use lighthouse_network::SyncInfo;
use slog::{crit, debug, error};
use smallvec::SmallVec;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use types::EthSpec;
use types::{Epoch, Hash256, Slot};

/// The number of head syncing chains to sync at a time.
const PARALLEL_HEAD_CHAINS: usize = 2;

/// Minimum work we require a finalized chain to do before picking a chain with more peers.
const MIN_FINALIZED_CHAIN_VALIDATED_EPOCHS: u64 = 10;

/// The state of the long range/batch sync.
#[derive(Clone)]
pub enum RangeSyncState {
    /// A finalized chain is being synced.
    Finalized(u64),
    /// There are no finalized chains and we are syncing one more head chains.
    Head(SmallVec<[u64; PARALLEL_HEAD_CHAINS]>),
    /// There are no head or finalized chains and no long range sync is in progress.
    Idle,
}

/// A collection of finalized and head chains currently being processed.
pub struct ChainCollection<T: BeaconChainTypes, C> {
    /// The beacon chain for processing.
    beacon_chain: Arc<C>,
    /// The set of finalized chains being synced.
    finalized_chains: FnvHashMap<ChainId, SyncingChain<T>>,
    /// The set of head chains being synced.
    head_chains: FnvHashMap<ChainId, SyncingChain<T>>,
    /// The current sync state of the process.
    state: RangeSyncState,
    /// Logger for the collection.
    log: slog::Logger,
}

impl<T: BeaconChainTypes, C: BlockStorage> ChainCollection<T, C> {
    pub fn new(beacon_chain: Arc<C>, log: slog::Logger) -> Self {
        ChainCollection {
            beacon_chain,
            finalized_chains: FnvHashMap::default(),
            head_chains: FnvHashMap::default(),
            state: RangeSyncState::Idle,
            log,
        }
    }

    /// Updates the Syncing state of the collection after a chain is removed.
    fn on_chain_removed(&mut self, id: &ChainId, was_syncing: bool, sync_type: RangeSyncType) {
        let _ = metrics::get_int_gauge(&metrics::SYNCING_CHAINS_COUNT, &[sync_type.as_str()])
            .map(|m| m.dec());

        match self.state {
            RangeSyncState::Finalized(ref syncing_id) => {
                if syncing_id == id {
                    // the finalized chain that was syncing was removed
                    debug_assert!(was_syncing && sync_type == RangeSyncType::Finalized);
                    let syncing_head_ids: SmallVec<[u64; PARALLEL_HEAD_CHAINS]> = self
                        .head_chains
                        .iter()
                        .filter(|(_id, chain)| chain.is_syncing())
                        .map(|(id, _)| *id)
                        .collect();
                    self.state = if syncing_head_ids.is_empty() {
                        RangeSyncState::Idle
                    } else {
                        RangeSyncState::Head(syncing_head_ids)
                    };
                } else {
                    // we removed a head chain, or an stoped finalized chain
                    debug_assert!(!was_syncing || sync_type != RangeSyncType::Finalized);
                }
            }
            RangeSyncState::Head(ref mut syncing_head_ids) => {
                if let Some(index) = syncing_head_ids
                    .iter()
                    .enumerate()
                    .find(|(_, &chain_id)| &chain_id == id)
                    .map(|(i, _)| i)
                {
                    // a syncing head chain was removed
                    debug_assert!(was_syncing);
                    syncing_head_ids.swap_remove(index);
                    if syncing_head_ids.is_empty() {
                        self.state = RangeSyncState::Idle;
                    }
                } else {
                    debug_assert!(!was_syncing);
                }
            }
            RangeSyncState::Idle => {
                // the removed chain should not be syncing
                debug_assert!(!was_syncing)
            }
        }
    }

    /// Calls `func` on every chain of the collection. If the result is
    /// `ProcessingResult::RemoveChain`, the chain is removed and returned.
    /// NOTE: `func` must not change the syncing state of a chain.
    pub fn call_all<F>(&mut self, mut func: F) -> Vec<(SyncingChain<T>, RangeSyncType, RemoveChain)>
    where
        F: FnMut(&mut SyncingChain<T>) -> ProcessingResult,
    {
        let mut to_remove = Vec::new();

        for (id, chain) in self.finalized_chains.iter_mut() {
            if let Err(remove_reason) = func(chain) {
                to_remove.push((*id, RangeSyncType::Finalized, remove_reason));
            }
        }

        for (id, chain) in self.head_chains.iter_mut() {
            if let Err(remove_reason) = func(chain) {
                to_remove.push((*id, RangeSyncType::Head, remove_reason));
            }
        }

        let mut results = Vec::with_capacity(to_remove.len());
        for (id, sync_type, reason) in to_remove.into_iter() {
            let chain = match sync_type {
                RangeSyncType::Finalized => self.finalized_chains.remove(&id),
                RangeSyncType::Head => self.head_chains.remove(&id),
            };
            let chain = chain.expect("Chain exists");
            self.on_chain_removed(&id, chain.is_syncing(), sync_type);
            results.push((chain, sync_type, reason));
        }
        results
    }

    /// Executes a function on the chain with the given id.
    ///
    /// If the function returns `ProcessingResult::RemoveChain`, the chain is removed and returned.
    /// If the chain is found, its syncing type is returned, or an error otherwise.
    /// NOTE: `func` should not change the sync state of a chain.
    #[allow(clippy::type_complexity)]
    pub fn call_by_id<F>(
        &mut self,
        id: ChainId,
        func: F,
    ) -> Result<(Option<(SyncingChain<T>, RemoveChain)>, RangeSyncType), ()>
    where
        F: FnOnce(&mut SyncingChain<T>) -> ProcessingResult,
    {
        if let Entry::Occupied(mut entry) = self.finalized_chains.entry(id) {
            // Search in our finalized chains first
            if let Err(remove_reason) = func(entry.get_mut()) {
                let chain = entry.remove();
                self.on_chain_removed(&id, chain.is_syncing(), RangeSyncType::Finalized);
                Ok((Some((chain, remove_reason)), RangeSyncType::Finalized))
            } else {
                Ok((None, RangeSyncType::Finalized))
            }
        } else if let Entry::Occupied(mut entry) = self.head_chains.entry(id) {
            // Search in our head chains next
            if let Err(remove_reason) = func(entry.get_mut()) {
                let chain = entry.remove();
                self.on_chain_removed(&id, chain.is_syncing(), RangeSyncType::Head);
                Ok((Some((chain, remove_reason)), RangeSyncType::Head))
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
    pub fn update(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        local: &SyncInfo,
        awaiting_head_peers: &mut HashMap<PeerId, SyncInfo>,
    ) {
        // Remove any outdated finalized/head chains
        self.purge_outdated_chains(local, awaiting_head_peers);

        let local_head_epoch = local.head_slot.epoch(T::EthSpec::slots_per_epoch());
        // Choose the best finalized chain if one needs to be selected.
        self.update_finalized_chains(network, local.finalized_epoch, local_head_epoch);

        if !matches!(self.state, RangeSyncState::Finalized(_)) {
            // Handle head syncing chains if there are no finalized chains left.
            self.update_head_chains(
                network,
                local.finalized_epoch,
                local_head_epoch,
                awaiting_head_peers,
            );
        }
    }

    pub fn state(
        &self,
    ) -> Result<Option<(RangeSyncType, Slot /* from */, Slot /* to */)>, &'static str> {
        match self.state {
            RangeSyncState::Finalized(ref syncing_id) => {
                let chain = self
                    .finalized_chains
                    .get(syncing_id)
                    .ok_or("Finalized syncing chain not found")?;
                Ok(Some((
                    RangeSyncType::Finalized,
                    chain.start_epoch.start_slot(T::EthSpec::slots_per_epoch()),
                    chain.target_head_slot,
                )))
            }
            RangeSyncState::Head(ref syncing_head_ids) => {
                let mut range: Option<(Slot, Slot)> = None;
                for id in syncing_head_ids {
                    let chain = self
                        .head_chains
                        .get(id)
                        .ok_or("Head syncing chain not found")?;
                    let start = chain.start_epoch.start_slot(T::EthSpec::slots_per_epoch());
                    let target = chain.target_head_slot;

                    range = range
                        .map(|(min_start, max_slot)| (min_start.min(start), max_slot.max(target)))
                        .or(Some((start, target)));
                }
                let (start_slot, target_slot) = range.ok_or("Syncing head with empty head ids")?;
                Ok(Some((RangeSyncType::Head, start_slot, target_slot)))
            }
            RangeSyncState::Idle => Ok(None),
        }
    }

    /// This looks at all current finalized chains and decides if a new chain should be prioritised
    /// or not.
    fn update_finalized_chains(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        local_epoch: Epoch,
        local_head_epoch: Epoch,
    ) {
        // Find the chain with most peers and check if it is already syncing
        if let Some((mut new_id, max_peers)) = self
            .finalized_chains
            .iter()
            .max_by_key(|(_, chain)| chain.available_peers())
            .map(|(id, chain)| (*id, chain.available_peers()))
        {
            let mut old_id = None;
            if let RangeSyncState::Finalized(syncing_id) = self.state {
                if syncing_id == new_id {
                    // best chain is already syncing
                    old_id = Some(None);
                } else {
                    // chains are different, check that they don't have the same number of peers
                    if let Some(syncing_chain) = self.finalized_chains.get_mut(&syncing_id) {
                        if max_peers > syncing_chain.available_peers()
                            && syncing_chain.validated_epochs()
                                > MIN_FINALIZED_CHAIN_VALIDATED_EPOCHS
                        {
                            syncing_chain.stop_syncing();
                            old_id = Some(Some(syncing_id));
                        } else {
                            // chains have the same number of peers, pick the currently syncing
                            // chain to avoid unnecesary switchings and try to advance it
                            new_id = syncing_id;
                            old_id = Some(None);
                        }
                    }
                }
            }

            let chain = self
                .finalized_chains
                .get_mut(&new_id)
                .expect("Chain exists");

            match old_id {
                Some(Some(old_id)) => debug!(self.log, "Switching finalized chains";
                    "old_id" => old_id, &chain),
                None => debug!(self.log, "Syncing new finalized chain"; &chain),
                Some(None) => {
                    // this is the same chain. We try to advance it.
                }
            }

            // update the state to a new finalized state
            self.state = RangeSyncState::Finalized(new_id);

            if let Err(remove_reason) = chain.start_syncing(network, local_epoch, local_head_epoch)
            {
                if remove_reason.is_critical() {
                    crit!(self.log, "Chain removed while switching chains"; "chain" => new_id, "reason" => ?remove_reason);
                } else {
                    // this happens only if sending a batch over the `network` fails a lot
                    error!(self.log, "Chain removed while switching chains"; "chain" => new_id, "reason" => ?remove_reason);
                }
                self.finalized_chains.remove(&new_id);
                self.on_chain_removed(&new_id, true, RangeSyncType::Finalized);
            }
        }
    }

    /// Start syncing any head chains if required.
    fn update_head_chains(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        local_epoch: Epoch,
        local_head_epoch: Epoch,
        awaiting_head_peers: &mut HashMap<PeerId, SyncInfo>,
    ) {
        // Include the awaiting head peers
        for (peer_id, peer_sync_info) in awaiting_head_peers.drain() {
            debug!(self.log, "including head peer");
            self.add_peer_or_create_chain(
                local_epoch,
                peer_sync_info.head_root,
                peer_sync_info.head_slot,
                peer_id,
                RangeSyncType::Head,
                network,
            );
        }

        if self.head_chains.is_empty() {
            // There are no finalized chains, update the state.
            self.state = RangeSyncState::Idle;
            return;
        }

        // Order chains by available peers, if two chains have the same number of peers, prefer one
        // that is already syncing
        let mut preferred_ids = self
            .head_chains
            .iter()
            .map(|(id, chain)| (chain.available_peers(), !chain.is_syncing(), *id))
            .collect::<Vec<_>>();
        preferred_ids.sort_unstable();

        let mut syncing_chains = SmallVec::<[u64; PARALLEL_HEAD_CHAINS]>::new();
        for (_, _, id) in preferred_ids {
            let chain = self.head_chains.get_mut(&id).expect("known chain");
            if syncing_chains.len() < PARALLEL_HEAD_CHAINS {
                // start this chain if it's not already syncing
                if !chain.is_syncing() {
                    debug!(self.log, "New head chain started syncing"; &chain);
                }
                if let Err(remove_reason) =
                    chain.start_syncing(network, local_epoch, local_head_epoch)
                {
                    self.head_chains.remove(&id);
                    if remove_reason.is_critical() {
                        crit!(self.log, "Chain removed while switching head chains"; "chain" => id, "reason" => ?remove_reason);
                    } else {
                        error!(self.log, "Chain removed while switching head chains"; "chain" => id, "reason" => ?remove_reason);
                    }
                } else {
                    syncing_chains.push(id);
                }
            } else {
                // stop any other chain
                chain.stop_syncing();
            }
        }

        self.state = if syncing_chains.is_empty() {
            RangeSyncState::Idle
        } else {
            RangeSyncState::Head(syncing_chains)
        };
    }

    /// Returns if `true` if any finalized chains exist, `false` otherwise.
    pub fn is_finalizing_sync(&self) -> bool {
        !self.finalized_chains.is_empty()
    }

    /// Removes any outdated finalized or head chains.
    /// This removes chains with no peers, or chains whose start block slot is less than our current
    /// finalized block slot. Peers that would create outdated chains are removed too.
    pub fn purge_outdated_chains(
        &mut self,
        local_info: &SyncInfo,
        awaiting_head_peers: &mut HashMap<PeerId, SyncInfo>,
    ) {
        let local_finalized_slot = local_info
            .finalized_epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        let beacon_chain = &self.beacon_chain;
        let log_ref = &self.log;

        let is_outdated = |target_slot: &Slot, target_root: &Hash256| {
            target_slot <= &local_finalized_slot || beacon_chain.is_block_known(target_root)
        };

        // Retain only head peers that remain relevant
        awaiting_head_peers.retain(|_peer_id, peer_sync_info| {
            !is_outdated(&peer_sync_info.head_slot, &peer_sync_info.head_root)
        });

        // Remove chains that are out-dated
        let mut removed_chains = Vec::new();
        removed_chains.extend(self.finalized_chains.iter().filter_map(|(id, chain)| {
            if is_outdated(&chain.target_head_slot, &chain.target_head_root)
                || chain.available_peers() == 0
            {
                debug!(log_ref, "Purging out of finalized chain"; &chain);
                Some((*id, chain.is_syncing(), RangeSyncType::Finalized))
            } else {
                None
            }
        }));

        removed_chains.extend(self.head_chains.iter().filter_map(|(id, chain)| {
            if is_outdated(&chain.target_head_slot, &chain.target_head_root)
                || chain.available_peers() == 0
            {
                debug!(log_ref, "Purging out of date head chain"; &chain);
                Some((*id, chain.is_syncing(), RangeSyncType::Head))
            } else {
                None
            }
        }));

        // update the state of the collection
        for (id, was_syncing, sync_type) in removed_chains {
            // remove each chain, updating the state for each removal.
            match sync_type {
                RangeSyncType::Finalized => self.finalized_chains.remove(&id),
                RangeSyncType::Head => self.head_chains.remove(&id),
            };
            self.on_chain_removed(&id, was_syncing, sync_type);
        }
    }

    /// Adds a peer to a chain with the given target, or creates a new syncing chain if it doesn't
    /// exists.
    #[allow(clippy::too_many_arguments)]
    pub fn add_peer_or_create_chain(
        &mut self,
        start_epoch: Epoch,
        target_head_root: Hash256,
        target_head_slot: Slot,
        peer: PeerId,
        sync_type: RangeSyncType,
        network: &mut SyncNetworkContext<T>,
    ) {
        let id = SyncingChain::<T>::id(&target_head_root, &target_head_slot);
        let (collection, is_finalized) = if let RangeSyncType::Finalized = sync_type {
            (&mut self.finalized_chains, true)
        } else {
            (&mut self.head_chains, false)
        };
        match collection.entry(id) {
            Entry::Occupied(mut entry) => {
                let chain = entry.get_mut();
                debug!(self.log, "Adding peer to known chain"; "peer_id" => %peer, "sync_type" => ?sync_type, &chain);
                debug_assert_eq!(chain.target_head_root, target_head_root);
                debug_assert_eq!(chain.target_head_slot, target_head_slot);
                if let Err(remove_reason) = chain.add_peer(network, peer) {
                    if remove_reason.is_critical() {
                        crit!(self.log, "Chain removed after adding peer"; "chain" => id, "reason" => ?remove_reason);
                    } else {
                        error!(self.log, "Chain removed after adding peer"; "chain" => id, "reason" => ?remove_reason);
                    }
                    let chain = entry.remove();
                    self.on_chain_removed(&id, chain.is_syncing(), sync_type);
                }
            }
            Entry::Vacant(entry) => {
                let peer_rpr = peer.to_string();
                let new_chain = SyncingChain::new(
                    start_epoch,
                    target_head_slot,
                    target_head_root,
                    peer,
                    is_finalized,
                    &self.log,
                );
                debug_assert_eq!(new_chain.get_id(), id);
                debug!(self.log, "New chain added to sync"; "peer_id" => peer_rpr, "sync_type" => ?sync_type, &new_chain);
                entry.insert(new_chain);
                let _ =
                    metrics::get_int_gauge(&metrics::SYNCING_CHAINS_COUNT, &[sync_type.as_str()])
                        .map(|m| m.inc());
            }
        }
    }
}
