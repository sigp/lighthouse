use crate::Error;
use lru::LruCache;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroUsize;
use types::{BeaconState, EthSpec, Hash256, Slot};

/// Maps block roots to a list of states that have been pre-emptively advanced
/// to future slots (i.e. `per_slot_processing` has been run on them).
///
/// For a given block at slot `n`, the 0th index of its corresponding `Vec` will
/// be at slot `n + 1`. The 1st index will be at slot `n + 2`, and so on.
type AdvancedStates<E> = HashMap<Hash256, Vec<StateWithRoot<E>>>;

#[derive(Debug, Clone)]
pub struct StateWithRoot<E: EthSpec> {
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
    /// Holds the finalized state separate to other states. The finalized state
    /// should never be dropped, just updated.
    finalized_state: Option<StateWithRoot<E>>,
    /// Holds a pool of recently-used states.
    states: LruCache<Hash256, BeaconState<E>>,
    /// Maps a block root to its appropriate state in `self.states` or
    /// `self.finalized_state`. Notably, this map will not return states in
    /// `self.advanced_states`.
    block_map: BlockMap,
    /// Contains states which have been pre-emptively advanced beyond the slot
    /// of their latest block.
    ///
    /// Advanced states are stored in their own special place to ensure that we
    /// retain either all or no states in a given "chain" of advanced states.
    advanced_states: AdvancedStates<E>,
}

#[derive(Debug)]
pub enum PutStateOutcome {
    Finalized,
    Duplicate,
    New,
}

impl<E: EthSpec> StateCache<E> {
    pub fn new(capacity: NonZeroUsize) -> Self {
        StateCache {
            finalized_state: None,
            states: LruCache::new(capacity),
            block_map: BlockMap::default(),
            advanced_states: AdvancedStates::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.states.len()
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
        self.finalized_state = Some(StateWithRoot { state_root, state });
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

    // Caches a `state` which has been "advanced" via `per_slot_processing` to
    // some slot later than `block_slot`.
    pub fn insert_advanced_state(
        &mut self,
        block_root: Hash256,
        block_slot: Slot,
        state_root: Hash256,
        state: BeaconState<E>,
    ) -> Result<(), Error> {
        let existing_states = self.advanced_states.entry(block_root).or_default();

        // Check that the given `state` is exactly one slot later than the
        // latest known slot. We assume that the state at `block_slot` is
        // already stored in the database.
        let previous_slot = existing_states
            .last()
            .map(|s| s.state.slot())
            .unwrap_or(block_slot);
        if previous_slot + 1 != state.slot() {
            return Err(Error::AdvancedStateMissesSlot {
                previous_slot,
                state_slot: state.slot(),
            });
        }

        existing_states.push(StateWithRoot { state_root, state });

        Ok(())
    }

    /// Returns a state which descends from `block_root` with a `slot` this
    /// *less than or equal to* the given `slot` (or `None`).
    pub fn get_best_advanced_state(
        &self,
        block_root: Hash256,
        slot: Slot,
    ) -> Option<(Hash256, BeaconState<E>)> {
        let states = self.advanced_states.get(&block_root)?;
        states
            .iter()
            // Try to return a state at the exact `slot`.
            .find(|state| state.state.slot() == slot)
            // If the exact slot doesn't exist, return the latest `state`. The
            // consistency conditions on advanced state insertion will guarantee
            // that this state has a slot lower that `slot`.
            .or_else(|| states.last())
            .cloned()
            .map(|StateWithRoot { state_root, state }| (state_root, state))
    }

    /// Drops all advanced states that do not descend from a root in
    /// `blocks_roots_to_retain`.
    pub fn prune_advanced_states(&mut self, blocks_roots_to_retain: &[Hash256]) {
        self.advanced_states
            .retain(|key, _value| blocks_roots_to_retain.iter().any(|root| key == root));
    }
}

impl BlockMap {
    fn insert(&mut self, block_root: Hash256, slot: Slot, state_root: Hash256) {
        let slot_map = self
            .blocks
            .entry(block_root)
            .or_insert_with(SlotMap::default);
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
