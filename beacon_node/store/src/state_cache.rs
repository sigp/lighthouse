use crate::Error;
use lru::LruCache;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroUsize;
use types::{BeaconState, ChainSpec, Epoch, EthSpec, Hash256, Slot};

/// Fraction of the LRU cache to leave intact during culling.
const CULL_EXEMPT_NUMERATOR: usize = 1;
const CULL_EXEMPT_DENOMINATOR: usize = 10;

/// States that are less than or equal to this many epochs old *could* become finalized and will not
/// be culled from the cache.
const EPOCH_FINALIZATION_LIMIT: u64 = 4;

#[derive(Debug)]
pub struct FinalizedState<E: EthSpec> {
    state_root: Hash256,
    state: BeaconState<E>,
}

/// Map from block_root -> slot -> state_root.
#[derive(Debug, Default)]
pub struct BlockMap {
    blocks: HashMap<Hash256, SlotMap>,
}

/// Map from slot -> state_root.
#[derive(Debug, Default)]
pub struct SlotMap {
    slots: BTreeMap<Slot, Hash256>,
}

#[derive(Debug)]
pub struct StateCache<E: EthSpec> {
    finalized_state: Option<FinalizedState<E>>,
    states: LruCache<Hash256, BeaconState<E>>,
    block_map: BlockMap,
    max_epoch: Epoch,
}

#[derive(Debug)]
pub enum PutStateOutcome {
    Finalized,
    Duplicate,
    New,
}

#[allow(clippy::len_without_is_empty)]
impl<E: EthSpec> StateCache<E> {
    pub fn new(capacity: NonZeroUsize) -> Self {
        StateCache {
            finalized_state: None,
            states: LruCache::new(capacity),
            block_map: BlockMap::default(),
            max_epoch: Epoch::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn capacity(&self) -> usize {
        self.states.cap().get()
    }

    pub fn update_finalized_state(
        &mut self,
        state_root: Hash256,
        block_root: Hash256,
        state: BeaconState<E>,
    ) -> Result<(), Error> {
        if state.slot() % E::slots_per_epoch() != 0 {
            return Err(Error::FinalizedStateUnaligned);
        }

        if self
            .finalized_state
            .as_ref()
            .map_or(false, |finalized_state| {
                state.slot() < finalized_state.state.slot()
            })
        {
            return Err(Error::FinalizedStateDecreasingSlot);
        }

        // Add to block map.
        self.block_map.insert(block_root, state.slot(), state_root);

        // Prune block map.
        let state_roots_to_prune = self.block_map.prune(state.slot());

        // Delete states.
        for state_root in state_roots_to_prune {
            self.states.pop(&state_root);
        }

        // Update finalized state.
        self.finalized_state = Some(FinalizedState { state_root, state });
        Ok(())
    }

    /// Rebase the given state on the finalized state in order to reduce its memory consumption.
    ///
    /// This function should only be called on states that are likely not to already share tree
    /// nodes with the finalized state, e.g. states loaded from disk.
    ///
    /// If the finalized state is not initialized this function is a no-op.
    pub fn rebase_on_finalized(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if let Some(finalized_state) = &self.finalized_state {
            state.rebase_on(&finalized_state.state, spec)?;
        }
        Ok(())
    }

    /// Return a status indicating whether the state already existed in the cache.
    pub fn put_state(
        &mut self,
        state_root: Hash256,
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<PutStateOutcome, Error> {
        if self
            .finalized_state
            .as_ref()
            .map_or(false, |finalized_state| {
                finalized_state.state_root == state_root
            })
        {
            return Ok(PutStateOutcome::Finalized);
        }

        if self.states.peek(&state_root).is_some() {
            return Ok(PutStateOutcome::Duplicate);
        }

        // Refuse states with pending mutations: we want cached states to be as small as possible
        // i.e. stored entirely as a binary merkle tree with no updates overlaid.
        if state.has_pending_mutations() {
            return Err(Error::StateForCacheHasPendingUpdates {
                state_root,
                slot: state.slot(),
            });
        }

        // Update the cache's idea of the max epoch.
        self.max_epoch = std::cmp::max(state.current_epoch(), self.max_epoch);

        // If the cache is full, use the custom cull routine to make room.
        if let Some(over_capacity) = self.len().checked_sub(self.capacity()) {
            self.cull(over_capacity + 1);
        }

        // Insert the full state into the cache.
        self.states.put(state_root, state.clone());

        // Record the connection from block root and slot to this state.
        let slot = state.slot();
        self.block_map.insert(block_root, slot, state_root);

        Ok(PutStateOutcome::New)
    }

    pub fn get_by_state_root(&mut self, state_root: Hash256) -> Option<BeaconState<E>> {
        if let Some(ref finalized_state) = self.finalized_state {
            if state_root == finalized_state.state_root {
                return Some(finalized_state.state.clone());
            }
        }
        self.states.get(&state_root).cloned()
    }

    pub fn get_by_block_root(
        &mut self,
        block_root: Hash256,
        slot: Slot,
    ) -> Option<(Hash256, BeaconState<E>)> {
        let slot_map = self.block_map.blocks.get(&block_root)?;

        // Find the state at `slot`, or failing that the most recent ancestor.
        let state_root = slot_map
            .slots
            .iter()
            .rev()
            .find_map(|(ancestor_slot, state_root)| {
                (*ancestor_slot <= slot).then_some(*state_root)
            })?;

        let state = self.get_by_state_root(state_root)?;
        Some((state_root, state))
    }

    pub fn delete_state(&mut self, state_root: &Hash256) {
        self.states.pop(state_root);
        self.block_map.delete(state_root);
    }

    pub fn delete_block_states(&mut self, block_root: &Hash256) {
        if let Some(slot_map) = self.block_map.delete_block_states(block_root) {
            for state_root in slot_map.slots.values() {
                self.states.pop(state_root);
            }
        }
    }

    /// Cull approximately `count` states from the cache.
    ///
    /// States are culled LRU, with the following extra order imposed:
    ///
    /// - Advanced states.
    /// - Mid-epoch unadvanced states.
    /// - Epoch-boundary states that are too old to be finalized.
    /// - Epoch-boundary states that could be finalized.
    pub fn cull(&mut self, count: usize) {
        let cull_exempt = std::cmp::max(
            1,
            self.len() * CULL_EXEMPT_NUMERATOR / CULL_EXEMPT_DENOMINATOR,
        );

        // Stage 1: gather states to cull.
        let mut advanced_state_roots = vec![];
        let mut mid_epoch_state_roots = vec![];
        let mut old_boundary_state_roots = vec![];
        let mut good_boundary_state_roots = vec![];
        for (&state_root, state) in self.states.iter().skip(cull_exempt) {
            let is_advanced = state.slot() > state.latest_block_header().slot;
            let is_boundary = state.slot() % E::slots_per_epoch() == 0;
            let could_finalize =
                (self.max_epoch - state.current_epoch()) <= EPOCH_FINALIZATION_LIMIT;

            if is_boundary {
                if could_finalize {
                    good_boundary_state_roots.push(state_root);
                } else {
                    old_boundary_state_roots.push(state_root);
                }
            } else if is_advanced {
                advanced_state_roots.push(state_root);
            } else {
                mid_epoch_state_roots.push(state_root);
            }

            // Terminate early in the common case where we've already found enough junk to cull.
            if advanced_state_roots.len() == count {
                break;
            }
        }

        // Stage 2: delete.
        // This could probably be more efficient in how it interacts with the block map.
        for state_root in advanced_state_roots
            .iter()
            .chain(mid_epoch_state_roots.iter())
            .chain(old_boundary_state_roots.iter())
            .chain(good_boundary_state_roots.iter())
            .take(count)
        {
            self.delete_state(state_root);
        }
    }
}

impl BlockMap {
    fn insert(&mut self, block_root: Hash256, slot: Slot, state_root: Hash256) {
        let slot_map = self.blocks.entry(block_root).or_default();
        slot_map.slots.insert(slot, state_root);
    }

    fn prune(&mut self, finalized_slot: Slot) -> HashSet<Hash256> {
        let mut pruned_states = HashSet::new();

        self.blocks.retain(|_, slot_map| {
            slot_map.slots.retain(|slot, state_root| {
                let keep = *slot >= finalized_slot;
                if !keep {
                    pruned_states.insert(*state_root);
                }
                keep
            });

            !slot_map.slots.is_empty()
        });

        pruned_states
    }

    fn delete(&mut self, state_root_to_delete: &Hash256) {
        self.blocks.retain(|_, slot_map| {
            slot_map
                .slots
                .retain(|_, state_root| state_root != state_root_to_delete);
            !slot_map.slots.is_empty()
        });
    }

    fn delete_block_states(&mut self, block_root: &Hash256) -> Option<SlotMap> {
        self.blocks.remove(block_root)
    }
}
