use crate::Error;
use lru::LruCache;
use std::collections::{BTreeMap, HashMap, HashSet};
use types::{BeaconState, Epoch, EthSpec, Hash256, Slot};

#[derive(Debug)]
pub struct FinalizedState<E: EthSpec> {
    state_root: Hash256,
    epoch: Epoch,
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
        epoch: Epoch,
        state: BeaconState<E>,
    ) -> Result<(), Error> {
        if self
            .finalized_state
            .as_ref()
            .map_or(false, |finalized_state| epoch < finalized_state.epoch)
        {
            // FIXME(sproul): panic
            panic!("decreasing epoch");
        }

        let finalized_slot = epoch.start_slot(E::slots_per_epoch());

        // Add to block map.
        self.block_map
            .insert(block_root, finalized_slot, state_root);

        // Prune block map.
        let state_roots_to_prune = self.block_map.prune(finalized_slot);

        // Delete states.
        for state_root in state_roots_to_prune {
            self.states.pop(&state_root);
        }

        // Update finalized state.
        self.finalized_state = Some(FinalizedState {
            state_root,
            epoch,
            state,
        });
        Ok(())
    }

    /// Return a bool indicating whether the state already existed in the cache.
    pub fn put_state(
        &mut self,
        state_root: Hash256,
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<bool, Error> {
        if self
            .finalized_state
            .as_ref()
            .map_or(false, |finalized_state| {
                finalized_state.state_root == state_root
            })
        {
            return Ok(true);
        }
        if self.states.peek(&state_root).is_some() {
            return Ok(true);
        }

        // FIXME(sproul): remove zis
        assert!(
            !state.has_pending_mutations(),
            "what are you doing putting these filthy states in here?"
        );

        // Insert the full state into the cache.
        self.states.put(state_root, state.clone());

        // Record the connection from block root and slot to this state.
        let slot = state.slot();
        self.block_map.insert(block_root, slot, state_root);

        Ok(false)
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
                (*ancestor_slot <= slot).then(|| *state_root)
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

    // FIXME(sproul): slow, make generic
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

#[cfg(test)]
mod test {
    use super::*;
    use std::mem::size_of;
    use types::{
        beacon_state::PubkeyCache, BeaconBlockHeader, BeaconState, BeaconStateAltair,
        BeaconStateMerge, MainnetEthSpec,
    };

    #[test]
    fn state_size() {
        println!("{}", size_of::<BeaconStateAltair<MainnetEthSpec>>());
        println!("{}", size_of::<BeaconStateMerge<MainnetEthSpec>>());
        println!("{}", size_of::<BeaconState<MainnetEthSpec>>());
        println!("{}", size_of::<PubkeyCache>());
        assert!(false);
    }
}
