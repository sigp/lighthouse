use crate::Error;
use lru::LruCache;
use std::collections::{BTreeMap, HashMap, HashSet};
use types::{BeaconState, EthSpec, Hash256, Slot};

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
}

#[derive(Debug)]
pub enum PutStateOutcome {
    Finalized,
    Duplicate,
    New,
}

impl<E: EthSpec> StateCache<E> {
    pub fn new(capacity: usize) -> Self {
        StateCache {
            finalized_state: None,
            states: LruCache::new(capacity),
            block_map: BlockMap::default(),
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
        self.finalized_state = Some(FinalizedState { state_root, state });
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
