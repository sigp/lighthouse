use crate::Error;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use types::{BeaconState, ChainSpec, Epoch, EthSpec, Hash256, Slot};

/// Maximum number of states per block root
const MAX_STATES_PER_BLOCK: usize = 4;

/// Cached beacon state with associated metadata
#[derive(Debug)]
struct CachedState<E: EthSpec> {
    /// The block root that produced this state
    block_root: Hash256,
    /// The actual beacon state
    state: BeaconState<E>,
    /// Last access time (used for LRU eviction)
    last_accessed: u64,
}

/// A finalized state
#[derive(Debug)]
pub struct FinalizedState<E: EthSpec> {
    state_root: Hash256,
    state: BeaconState<E>,
}

/// A simplified state cache that maintains states indexed by both state root and block root
#[derive(Debug)]
pub struct StateCache<E: EthSpec> {
    /// The finalized state
    finalized_state: Option<FinalizedState<E>>,

    /// Access counter (incremented each time a state is accessed)
    access_counter: u64,

    /// Map from state root to cached state
    states_by_root: HashMap<Hash256, CachedState<E>>,

    /// Map from block root to a map of (slot -> state root)
    /// This allows efficient lookup by block root and slot
    block_to_states: HashMap<Hash256, HashMap<Slot, Hash256>>,

    /// Set of block roots that are directly linked to their ancestor blocks
    /// This tracks the block graph structure
    block_ancestry: HashMap<Hash256, Hash256>, // child -> parent

    /// Total capacity of the cache
    capacity: NonZeroUsize,

    /// Track max epoch for state pruning
    max_epoch: Epoch,
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
            access_counter: 0,
            states_by_root: HashMap::with_capacity(capacity.get()),
            block_to_states: HashMap::new(),
            block_ancestry: HashMap::new(),
            capacity,
            max_epoch: Epoch::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.states_by_root.len()
    }

    pub fn capacity(&self) -> usize {
        self.capacity.into()
    }

    /// Update the finalized state
    pub fn update_finalized_state(
        &mut self,
        state_root: Hash256,
        block_root: Hash256,
        state: BeaconState<E>,
    ) -> Result<(), Error> {
        // Verify the state is at an epoch boundary
        if state.slot() % E::slots_per_epoch() != 0 {
            return Err(Error::FinalizedStateUnaligned);
        }

        // Verify the new state is not older than the existing finalized state
        if self
            .finalized_state
            .as_ref()
            .is_some_and(|finalized_state| state.slot() < finalized_state.state.slot())
        {
            return Err(Error::FinalizedStateDecreasingSlot);
        }

        // Add finalized state to block->state mapping
        self.add_block_state_mapping(block_root, state.slot(), state_root);

        // Prune states below the finalized slot
        self.prune_states_before_slot(state.slot());

        // Update finalized state
        self.finalized_state = Some(FinalizedState { state_root, state });
        Ok(())
    }

    /// Rebase the given state on the finalized state to reduce memory consumption
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

    /// Store a state in the cache
    pub fn put_state(
        &mut self,
        state_root: Hash256,
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<PutStateOutcome, Error> {
        // Handle finalized state case
        if self
            .finalized_state
            .as_ref()
            .is_some_and(|finalized_state| finalized_state.state_root == state_root)
        {
            return Ok(PutStateOutcome::Finalized);
        }

        // First increment the counter
        let new_access_count = self.increment_access_counter();

        // Then check for duplicates and update in a single operation
        if let Some(cached_state) = self.states_by_root.get_mut(&state_root) {
            cached_state.last_accessed = new_access_count;
            return Ok(PutStateOutcome::Duplicate);
        }

        // Reject states with pending mutations
        if state.has_pending_mutations() {
            return Err(Error::StateForCacheHasPendingUpdates {
                state_root,
                slot: state.slot(),
            });
        }

        // Update the cache's max epoch
        self.max_epoch = std::cmp::max(state.current_epoch(), self.max_epoch);

        // Examine the state's block roots to update our block ancestry graph
        self.update_block_ancestry(block_root, state);

        // Add the state to the cache
        let cached_state = CachedState {
            block_root,
            state: state.clone(),
            last_accessed: self.increment_access_counter(),
        };

        // Ensure we have capacity
        if self.states_by_root.len() >= self.capacity.get() {
            self.evict_lru_state();
        }

        // Add the state to our mappings
        self.states_by_root.insert(state_root, cached_state);
        self.add_block_state_mapping(block_root, state.slot(), state_root);

        Ok(PutStateOutcome::New)
    }

    /// Update block ancestry information based on a state's block roots
    fn update_block_ancestry(&mut self, block_root: Hash256, state: &BeaconState<E>) {
        // Extract block roots from the state to update our ancestry graph
        for i in 0..state.block_roots().len() {
            let slot = state.slot().saturating_sub(i as u64 + 1);
            if slot >= state.slot() {
                continue; // Skip invalid slots
            }

            if let Ok(ancestor_root) = state.get_block_root(slot) {
                if *ancestor_root != Hash256::ZERO && *ancestor_root != block_root {
                    // Update our ancestry graph: block_root's parent at this slot is ancestor_root
                    self.block_ancestry.insert(block_root, *ancestor_root);
                    break; // We only need the immediate parent
                }
            }
        }
    }

    /// Add a mapping from block root and slot to state root
    fn add_block_state_mapping(&mut self, block_root: Hash256, slot: Slot, state_root: Hash256) {
        // Get or create the slot -> state_root map for this block
        let slot_map = self
            .block_to_states
            .entry(block_root)
            .or_insert_with(HashMap::new);

        // Add or update the mapping
        slot_map.insert(slot, state_root);

        // Ensure we don't exceed MAX_STATES_PER_BLOCK for this block
        if slot_map.len() > MAX_STATES_PER_BLOCK {
            // Find the oldest slot (we want to keep the newest ones)
            if let Some(oldest_slot) = slot_map.keys().min().cloned() {
                // Only remove if it's not the slot we just added
                if oldest_slot != slot {
                    if let Some(old_state_root) = slot_map.remove(&oldest_slot) {
                        // Check if this state root is still needed by other blocks
                        let still_needed = self
                            .block_to_states
                            .values()
                            .any(|map| map.values().any(|&sr| sr == old_state_root));

                        // If not needed, remove it from the states_by_root map too
                        if !still_needed && old_state_root != state_root {
                            self.states_by_root.remove(&old_state_root);
                        }
                    }
                }
            }
        }
    }

    /// Increment and return the access counter
    fn increment_access_counter(&mut self) -> u64 {
        self.access_counter += 1;
        self.access_counter
    }

    /// Evict the least recently used state
    fn evict_lru_state(&mut self) {
        // Find the state with the lowest last_accessed value
        if let Some(lru_state_root) = self
            .states_by_root
            .iter()
            .min_by_key(|(_, state)| state.last_accessed)
            .map(|(root, _)| *root)
        {
            // Remove the state
            if let Some(state) = self.states_by_root.remove(&lru_state_root) {
                // Also clean up the block_to_states mapping
                if let Some(slot_map) = self.block_to_states.get_mut(&state.block_root) {
                    // Find and remove the entry for this state root
                    let slots_to_remove: Vec<_> = slot_map
                        .iter()
                        .filter_map(|(&slot, &sr)| {
                            if sr == lru_state_root {
                                Some(slot)
                            } else {
                                None
                            }
                        })
                        .collect();

                    for slot in slots_to_remove {
                        slot_map.remove(&slot);
                    }

                    // Remove the block entry if it's now empty
                    if slot_map.is_empty() {
                        self.block_to_states.remove(&state.block_root);
                    }
                }
            }
        }
    }

    /// Prune states with slots before the given slot
    fn prune_states_before_slot(&mut self, slot: Slot) {
        // Collect state roots to remove
        let roots_to_remove: Vec<_> = self
            .states_by_root
            .iter()
            .filter_map(|(root, state)| {
                if state.state.slot() < slot {
                    Some(*root)
                } else {
                    None
                }
            })
            .collect();

        // Remove the states
        for root in roots_to_remove {
            if let Some(state) = self.states_by_root.remove(&root) {
                // Clean up block_to_states mapping
                if let Some(slot_map) = self.block_to_states.get_mut(&state.block_root) {
                    // Find and remove entries for this state root
                    let slots_to_remove: Vec<_> = slot_map
                        .iter()
                        .filter_map(|(&s, &sr)| if sr == root { Some(s) } else { None })
                        .collect();

                    for s in slots_to_remove {
                        slot_map.remove(&s);
                    }

                    // Remove block entry if empty
                    if slot_map.is_empty() {
                        self.block_to_states.remove(&state.block_root);
                    }
                }
            }
        }
    }

    /// Get a state by its root
    pub fn get_by_state_root(&mut self, state_root: Hash256) -> Option<BeaconState<E>> {
        // Check finalized state first
        if let Some(ref finalized_state) = self.finalized_state {
            if state_root == finalized_state.state_root {
                return Some(finalized_state.state.clone());
            }
        }

        let new_access_count = self.increment_access_counter(); // Look up in the states map
        if let Some(cached_state) = self.states_by_root.get_mut(&state_root) {
            // Update access time
            cached_state.last_accessed = new_access_count;
            return Some(cached_state.state.clone());
        }

        None
    }

    /// Get a state by block root and slot
    pub fn get_by_block_root(
        &mut self,
        block_root: Hash256,
        slot: Slot,
    ) -> Option<(Hash256, BeaconState<E>)> {
        // Look up states for this block
        let slot_map = self.block_to_states.get(&block_root)?;

        // Find exact match or closest ancestor
        let mut best_slot = None;
        let mut best_state_root = None;

        for (&s, &sr) in slot_map.iter() {
            if s <= slot && (best_slot.is_none() || s > best_slot.unwrap()) {
                best_slot = Some(s);
                best_state_root = Some(sr);
            }
        }

        // If we found a matching state root, get the state
        if let Some(state_root) = best_state_root {
            if let Some(state) = self.get_by_state_root(state_root) {
                return Some((state_root, state));
            }
        }

        None
    }

    /// Delete a state by its root
    pub fn delete_state(&mut self, state_root: &Hash256) {
        if let Some(state) = self.states_by_root.remove(state_root) {
            // Clean up block_to_states mapping
            if let Some(slot_map) = self.block_to_states.get_mut(&state.block_root) {
                // Find and remove entries for this state root
                let slots_to_remove: Vec<_> = slot_map
                    .iter()
                    .filter_map(|(&s, &sr)| if sr == *state_root { Some(s) } else { None })
                    .collect();

                for s in slots_to_remove {
                    slot_map.remove(&s);
                }

                // Remove block entry if empty
                if slot_map.is_empty() {
                    self.block_to_states.remove(&state.block_root);
                }
            }
        }
    }

    /// Delete all states associated with a block
    pub fn delete_block_states(&mut self, block_root: &Hash256) {
        if let Some(slot_map) = self.block_to_states.remove(block_root) {
            // For each state root referenced by this block
            for &state_root in slot_map.values() {
                // Check if this state root is still referenced by other blocks
                let still_referenced = self
                    .block_to_states
                    .values()
                    .any(|map| map.values().any(|&sr| sr == state_root));

                // If not referenced, remove the state
                if !still_referenced {
                    self.states_by_root.remove(&state_root);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;
    use types::*;

    fn hash(index: u16) -> Hash256 {
        let mut bytes = [0; 32];
        bytes[0] = (index & 0xFF) as u8;
        bytes[1] = ((index >> 8) & 0xFF) as u8;
        Hash256::from(bytes)
    }

    fn make_test_state<E: EthSpec>(slot: u64, block_roots: Vec<(u64, Hash256)>) -> BeaconState<E> {
        let spec = &ChainSpec::minimal();
        let mut state = BeaconState::new(0, Default::default(), spec);
        *state.slot_mut() = Slot::new(slot);

        // Inject block roots into the state's history
        for (root_slot, root) in block_roots {
            state.set_block_root(Slot::new(root_slot), root).unwrap();
        }

        state.apply_pending_mutations().unwrap();

        state
    }

    #[test]
    fn test_basic_state_storage() {
        let mut cache = StateCache::<MinimalEthSpec>::new(NonZeroUsize::new(100).unwrap());

        // Create and store a simple state
        let block_root = hash(1);
        let state_root = hash(101);
        let state = make_test_state::<MinimalEthSpec>(1, vec![]);

        let result = cache.put_state(state_root, block_root, &state);
        assert!(matches!(result, Ok(PutStateOutcome::New)));

        // Verify we can retrieve it
        let retrieved = cache.get_by_state_root(state_root);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().slot(), state.slot());

        // Store the next state in the chain
        let block_root2 = hash(2);
        let state_root2 = hash(102);
        let state2 = make_test_state::<MinimalEthSpec>(2, vec![(1, block_root)]);

        let result = cache.put_state(state_root2, block_root2, &state2);
        assert!(matches!(result, Ok(PutStateOutcome::New)));

        // Verify both states exist in the cache
        assert!(cache.get_by_state_root(state_root).is_some());
        assert!(cache.get_by_state_root(state_root2).is_some());

        // Block ancestry should show block2 has block1 as parent
        assert_eq!(cache.block_ancestry.get(&block_root2), Some(&block_root));
    }

    #[test]
    fn test_basic_state_storage_reverse_order() {
        let mut cache = StateCache::<MinimalEthSpec>::new(NonZeroUsize::new(100).unwrap());

        let block_root = hash(1);
        let state_root = hash(101);
        let state = make_test_state::<MinimalEthSpec>(1, vec![]);

        let block_root2 = hash(2);
        let state_root2 = hash(102);
        let state2 = make_test_state::<MinimalEthSpec>(2, vec![(1, block_root)]);

        let result = cache.put_state(state_root2, block_root2, &state2);
        assert!(matches!(result, Ok(PutStateOutcome::New)));

        let result = cache.put_state(state_root, block_root, &state);
        assert!(matches!(result, Ok(PutStateOutcome::New)));

        let retrieved = cache.get_by_state_root(state_root);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().slot(), state.slot());

        assert!(cache.get_by_state_root(state_root).is_some());
        assert!(cache.get_by_state_root(state_root2).is_some());

        // Block ancestry should be updated correctly
        assert_eq!(cache.block_ancestry.get(&block_root2), Some(&block_root));
    }

    #[test]
    fn test_block_ancestry_detection() {
        let mut cache = StateCache::<MinimalEthSpec>::new(NonZeroUsize::new(100).unwrap());

        // Create a chain of blocks
        let block_root1 = hash(1);
        let block_root2 = hash(2);
        let block_root3 = hash(3);

        // State produced by block 1
        let state_root1 = hash(101);
        let state1 = make_test_state::<MinimalEthSpec>(1, vec![]);

        // State produced by block 2, which builds on block 1
        let state_root2 = hash(102);
        let state2 = make_test_state::<MinimalEthSpec>(2, vec![(1, block_root1)]);

        // State produced by block 3, which builds on block 2
        let state_root3 = hash(103);
        let state3 = make_test_state::<MinimalEthSpec>(3, vec![(1, block_root1), (2, block_root2)]);

        // Add states to the cache
        cache.put_state(state_root1, block_root1, &state1).unwrap();
        cache.put_state(state_root2, block_root2, &state2).unwrap();
        cache.put_state(state_root3, block_root3, &state3).unwrap();

        // Verify block ancestry is tracked correctly
        assert_eq!(cache.block_ancestry.get(&block_root2), Some(&block_root1));
        assert_eq!(cache.block_ancestry.get(&block_root3), Some(&block_root2));

        // Verify all states are stored
        assert!(cache.states_by_root.contains_key(&state_root1));
        assert!(cache.states_by_root.contains_key(&state_root2));
        assert!(cache.states_by_root.contains_key(&state_root3));

        // Verify block to state mappings
        assert!(cache.block_to_states.contains_key(&block_root1));
        assert!(cache.block_to_states.contains_key(&block_root2));
        assert!(cache.block_to_states.contains_key(&block_root3));
    }

    #[test]
    fn test_fork_handling() {
        let mut cache = StateCache::<MinimalEthSpec>::new(NonZeroUsize::new(100).unwrap());

        // Create a fork scenario:
        // block1 -> block2a -> block3a
        //        -> block2b -> block3b

        let block_root1 = hash(1);
        let block_root2a = hash(2);
        let block_root3a = hash(3);
        let block_root2b = hash(4);
        let block_root3b = hash(5);

        // State produced by block 1
        let state_root1 = hash(101);
        let state1 = make_test_state::<MinimalEthSpec>(1, vec![]);

        // States in fork A
        let state_root2a = hash(102);
        let state2a = make_test_state::<MinimalEthSpec>(2, vec![(1, block_root1)]);

        let state_root3a = hash(103);
        let state3a =
            make_test_state::<MinimalEthSpec>(3, vec![(1, block_root1), (2, block_root2a)]);

        // States in fork B
        let state_root2b = hash(104);
        let state2b = make_test_state::<MinimalEthSpec>(2, vec![(1, block_root1)]);

        let state_root3b = hash(105);
        let state3b =
            make_test_state::<MinimalEthSpec>(3, vec![(1, block_root1), (2, block_root2b)]);

        // Add states to the cache
        cache.put_state(state_root1, block_root1, &state1).unwrap();
        cache
            .put_state(state_root2a, block_root2a, &state2a)
            .unwrap();
        cache
            .put_state(state_root3a, block_root3a, &state3a)
            .unwrap();
        cache
            .put_state(state_root2b, block_root2b, &state2b)
            .unwrap();
        cache
            .put_state(state_root3b, block_root3b, &state3b)
            .unwrap();

        // Verify all states are in the cache
        assert!(cache.get_by_state_root(state_root1).is_some());
        assert!(cache.get_by_state_root(state_root2a).is_some());
        assert!(cache.get_by_state_root(state_root3a).is_some());
        assert!(cache.get_by_state_root(state_root2b).is_some());
        assert!(cache.get_by_state_root(state_root3b).is_some());

        // Verify block ancestry for the forks
        assert_eq!(cache.block_ancestry.get(&block_root2a), Some(&block_root1));
        assert_eq!(cache.block_ancestry.get(&block_root3a), Some(&block_root2a));
        assert_eq!(cache.block_ancestry.get(&block_root2b), Some(&block_root1));
        assert_eq!(cache.block_ancestry.get(&block_root3b), Some(&block_root2b));
    }

    #[test]
    fn test_block_lookup() {
        let mut cache = StateCache::<MinimalEthSpec>::new(NonZeroUsize::new(100).unwrap());

        // Create a block with multiple states at different slots
        let block_root = hash(1);

        // State at slot 10
        let state_root10 = hash(110);
        let state10 = make_test_state::<MinimalEthSpec>(10, vec![]);
        cache.put_state(state_root10, block_root, &state10).unwrap();

        // State at slot 20
        let state_root20 = hash(120);
        let state20 = make_test_state::<MinimalEthSpec>(20, vec![(10, block_root)]);
        cache.put_state(state_root20, block_root, &state20).unwrap();

        // Verify lookup at exact slot
        let (root, state) = cache.get_by_block_root(block_root, Slot::new(20)).unwrap();
        assert_eq!(root, state_root20);
        assert_eq!(state.slot(), Slot::new(20));

        // Verify lookup at intermediate slot (should return state at slot 10)
        let (root, state) = cache.get_by_block_root(block_root, Slot::new(15)).unwrap();
        assert_eq!(root, state_root10);
        assert_eq!(state.slot(), Slot::new(10));

        // Verify lookup at future slot (should return state at slot 20)
        let (root, state) = cache.get_by_block_root(block_root, Slot::new(25)).unwrap();
        assert_eq!(root, state_root20);
        assert_eq!(state.slot(), Slot::new(20));
    }

    #[test]
    fn test_lru_eviction() {
        // Create a cache with capacity for 3 states
        let mut cache = StateCache::<MinimalEthSpec>::new(NonZeroUsize::new(3).unwrap());

        // Create 3 states
        for i in 1..=3 {
            let block_root = hash(i);
            let state_root = hash(i + 100);
            let state = make_test_state::<MinimalEthSpec>(i as u64, vec![]);
            cache.put_state(state_root, block_root, &state).unwrap();
        }

        // Cache should have 3 states now
        assert_eq!(cache.states_by_root.len(), 3);

        // Access states in order: 3, 1, 2
        cache.get_by_state_root(hash(103));
        cache.get_by_state_root(hash(101));
        cache.get_by_state_root(hash(102));

        // Add a 4th state, which should evict the least recently used (state 3)
        let block_root4 = hash(4);
        let state_root4 = hash(104);
        let state4 = make_test_state::<MinimalEthSpec>(4, vec![]);
        cache.put_state(state_root4, block_root4, &state4).unwrap();

        // Should still have 3 states total
        assert_eq!(cache.states_by_root.len(), 3);

        // State 3 should be evicted
        assert!(!cache.states_by_root.contains_key(&hash(103)));

        // The other states should still be there
        assert!(cache.states_by_root.contains_key(&hash(101)));
        assert!(cache.states_by_root.contains_key(&hash(102)));
        assert!(cache.states_by_root.contains_key(&hash(104)));
    }

    #[test]
    fn test_state_limit_per_block() {
        let mut cache = StateCache::<MinimalEthSpec>::new(NonZeroUsize::new(100).unwrap());

        // Create a single block with 5 states (exceeding the per-block limit of 4)
        let block_root = hash(1);

        // Add 5 states for this block at different slots
        for i in 1..=(MAX_STATES_PER_BLOCK + 1) {
            let state_root = hash((100 + i) as u16);
            let state = make_test_state::<MinimalEthSpec>(i as u64, vec![]);
            cache.put_state(state_root, block_root, &state).unwrap();
        }

        // Should have only MAX_STATES_PER_BLOCK states for this block
        assert_eq!(
            cache.block_to_states.get(&block_root).unwrap().len(),
            MAX_STATES_PER_BLOCK
        );

        // The oldest state (state_root 101) should be evicted
        assert!(!cache.states_by_root.contains_key(&hash(101)));

        // The newest states should still be there
        assert!(cache.states_by_root.contains_key(&hash(102)));
        assert!(cache.states_by_root.contains_key(&hash(103)));
        assert!(cache.states_by_root.contains_key(&hash(104)));
        assert!(cache.states_by_root.contains_key(&hash(105)));
    }

    #[test]
    fn test_finalized_state() {
        let mut cache = StateCache::<MinimalEthSpec>::new(NonZeroUsize::new(100).unwrap());

        // Create a state at an epoch boundary (assuming 8 slots per epoch for MinimalEthSpec)
        let state = make_test_state::<MinimalEthSpec>(8, vec![]);
        let state_root = hash(100);
        let block_root = hash(1);

        // Update it as the finalized state
        let result = cache.update_finalized_state(state_root, block_root, state.clone());
        assert!(result.is_ok());

        // Verify we can retrieve it
        let retrieved_state = cache.get_by_state_root(state_root).unwrap();
        assert_eq!(retrieved_state.slot(), state.slot());

        // Try to put the same state again - should return Finalized
        let result = cache.put_state(state_root, block_root, &state).unwrap();
        assert!(matches!(result, PutStateOutcome::Finalized));
    }

    #[test]
    fn test_state_pruning_on_finalization() {
        let mut cache = StateCache::<MinimalEthSpec>::new(NonZeroUsize::new(100).unwrap());

        // Add states at different slots
        for i in 1..=9 {
            let block_root = hash(i);
            let state_root = hash(i + 100);
            let state = make_test_state::<MinimalEthSpec>(i as u64, vec![]);
            cache.put_state(state_root, block_root, &state).unwrap();
        }

        // Finalize a state at slot 8
        let finalized_state = make_test_state::<MinimalEthSpec>(8, vec![]); // Slot 8 is an epoch boundary
        let finalized_state_root = hash(108);
        let finalized_block_root = hash(8);

        cache
            .update_finalized_state(finalized_state_root, finalized_block_root, finalized_state)
            .unwrap();

        // States prior to slot 8 should be pruned
        assert!(!cache.states_by_root.contains_key(&hash(101)));
        assert!(!cache.states_by_root.contains_key(&hash(102)));
        assert!(!cache.states_by_root.contains_key(&hash(103)));
        assert!(!cache.states_by_root.contains_key(&hash(104)));
        assert!(!cache.states_by_root.contains_key(&hash(105)));
        assert!(!cache.states_by_root.contains_key(&hash(106)));
        assert!(!cache.states_by_root.contains_key(&hash(107)));

        // Finalized state and later states should still be present
        assert!(cache.finalized_state.is_some());
        assert!(cache.states_by_root.contains_key(&hash(109)));

        // Block to state mappings for pruned states should be gone
        for i in 1..=7 {
            let block_root = hash(i);
            if let Some(slot_map) = cache.block_to_states.get(&block_root) {
                // If the map exists, it shouldn't contain any references to pruned states
                for slot in 1..=7 {
                    assert!(!slot_map.contains_key(&Slot::new(slot)));
                }
            }
        }

        // Finalized state should be accessible
        assert!(cache.get_by_state_root(finalized_state_root).is_some());
    }

    #[test]
    fn test_delete_state() {
        let mut cache = StateCache::<MinimalEthSpec>::new(NonZeroUsize::new(100).unwrap());

        // Create and store a simple state
        let block_root = hash(1);
        let state_root = hash(101);
        let state = make_test_state::<MinimalEthSpec>(1, vec![]);

        cache.put_state(state_root, block_root, &state).unwrap();

        // Verify it's in the cache
        assert!(cache.states_by_root.contains_key(&state_root));
        assert!(cache.block_to_states.contains_key(&block_root));

        // Delete the state
        cache.delete_state(&state_root);

        // Verify it's removed from the cache
        assert!(!cache.states_by_root.contains_key(&state_root));

        // Block mapping should be updated
        if let Some(slot_map) = cache.block_to_states.get(&block_root) {
            assert!(!slot_map.values().any(|&sr| sr == state_root));
            if slot_map.is_empty() {
                assert!(!cache.block_to_states.contains_key(&block_root));
            }
        }
    }

    #[test]
    fn test_delete_block_states() {
        let mut cache = StateCache::<MinimalEthSpec>::new(NonZeroUsize::new(100).unwrap());

        // Create a block with multiple states
        let block_root = hash(1);

        // Add 3 states for this block
        for i in 1..=3 {
            let state_root = hash((100 + i) as u16);
            let state = make_test_state::<MinimalEthSpec>(i as u64, vec![]);
            cache.put_state(state_root, block_root, &state).unwrap();
        }

        // Verify the states are in the cache
        assert!(cache.states_by_root.contains_key(&hash(101)));
        assert!(cache.states_by_root.contains_key(&hash(102)));
        assert!(cache.states_by_root.contains_key(&hash(103)));

        // Delete all states for this block
        cache.delete_block_states(&block_root);

        // Verify the block mapping is removed
        assert!(!cache.block_to_states.contains_key(&block_root));

        // Verify all states are removed
        assert!(!cache.states_by_root.contains_key(&hash(101)));
        assert!(!cache.states_by_root.contains_key(&hash(102)));
        assert!(!cache.states_by_root.contains_key(&hash(103)));
    }
}
