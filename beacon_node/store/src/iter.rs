use crate::Store;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;
use types::{
    typenum::Unsigned, BeaconBlock, BeaconState, BeaconStateError, EthSpec, Hash256, Slot,
};

/// Implemented for types that have ancestors (e.g., blocks, states) that may be iterated over.
///
/// ## Note
///
/// It is assumed that all ancestors for this object are stored in the database. If this is not the
/// case, the iterator will start returning `None` prior to genesis.
pub trait AncestorIter<U: Store<E>, E: EthSpec, I: Iterator> {
    /// Returns an iterator over the roots of the ancestors of `self`.
    fn try_iter_ancestor_roots(&self, store: Arc<U>) -> Option<I>;
}

impl<'a, U: Store<E>, E: EthSpec> AncestorIter<U, E, BlockRootsIterator<'a, E, U>>
    for BeaconBlock<E>
{
    /// Iterates across all available prior block roots of `self`, starting at the most recent and ending
    /// at genesis.
    fn try_iter_ancestor_roots(&self, store: Arc<U>) -> Option<BlockRootsIterator<'a, E, U>> {
        let state = store.get_state(&self.state_root, Some(self.slot)).ok()??;

        Some(BlockRootsIterator::owned(store, state))
    }
}

impl<'a, U: Store<E>, E: EthSpec> AncestorIter<U, E, StateRootsIterator<'a, E, U>>
    for BeaconState<E>
{
    /// Iterates across all available prior state roots of `self`, starting at the most recent and ending
    /// at genesis.
    fn try_iter_ancestor_roots(&self, store: Arc<U>) -> Option<StateRootsIterator<'a, E, U>> {
        // The `self.clone()` here is wasteful.
        Some(StateRootsIterator::owned(store, self.clone()))
    }
}

pub struct StateRootsIterator<'a, T: EthSpec, U> {
    store: Arc<U>,
    beacon_state: Cow<'a, BeaconState<T>>,
    slot: Slot,
}

impl<'a, T: EthSpec, U> Clone for StateRootsIterator<'a, T, U> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            beacon_state: self.beacon_state.clone(),
            slot: self.slot,
        }
    }
}

impl<'a, T: EthSpec, U: Store<T>> StateRootsIterator<'a, T, U> {
    pub fn new(store: Arc<U>, beacon_state: &'a BeaconState<T>) -> Self {
        Self {
            store,
            slot: beacon_state.slot,
            beacon_state: Cow::Borrowed(beacon_state),
        }
    }

    pub fn owned(store: Arc<U>, beacon_state: BeaconState<T>) -> Self {
        Self {
            store,
            slot: beacon_state.slot,
            beacon_state: Cow::Owned(beacon_state),
        }
    }
}

impl<'a, T: EthSpec, U: Store<T>> Iterator for StateRootsIterator<'a, T, U> {
    type Item = (Hash256, Slot);

    fn next(&mut self) -> Option<Self::Item> {
        if self.slot == 0 || self.slot > self.beacon_state.slot {
            return None;
        }

        self.slot -= 1;

        match self.beacon_state.get_state_root(self.slot) {
            Ok(root) => Some((*root, self.slot)),
            Err(BeaconStateError::SlotOutOfBounds) => {
                // Read a `BeaconState` from the store that has access to prior historical roots.
                let beacon_state =
                    next_historical_root_backtrack_state(&*self.store, &self.beacon_state)?;

                self.beacon_state = Cow::Owned(beacon_state);

                let root = self.beacon_state.get_state_root(self.slot).ok()?;

                Some((*root, self.slot))
            }
            _ => None,
        }
    }
}

/// Block iterator that uses the `parent_root` of each block to backtrack.
pub struct ParentRootBlockIterator<'a, E: EthSpec, S: Store<E>> {
    store: &'a S,
    next_block_root: Hash256,
    _phantom: PhantomData<E>,
}

impl<'a, E: EthSpec, S: Store<E>> ParentRootBlockIterator<'a, E, S> {
    pub fn new(store: &'a S, start_block_root: Hash256) -> Self {
        Self {
            store,
            next_block_root: start_block_root,
            _phantom: PhantomData,
        }
    }
}

impl<'a, E: EthSpec, S: Store<E>> Iterator for ParentRootBlockIterator<'a, E, S> {
    type Item = BeaconBlock<E>;

    fn next(&mut self) -> Option<Self::Item> {
        // Stop once we reach the zero parent, otherwise we'll keep returning the genesis
        // block forever.
        if self.next_block_root.is_zero() {
            None
        } else {
            let block: BeaconBlock<E> = self.store.get(&self.next_block_root).ok()??;
            self.next_block_root = block.parent_root;
            Some(block)
        }
    }
}

#[derive(Clone)]
/// Extends `BlockRootsIterator`, returning `BeaconBlock` instances, instead of their roots.
pub struct BlockIterator<'a, T: EthSpec, U> {
    roots: BlockRootsIterator<'a, T, U>,
}

impl<'a, T: EthSpec, U: Store<T>> BlockIterator<'a, T, U> {
    /// Create a new iterator over all blocks in the given `beacon_state` and prior states.
    pub fn new(store: Arc<U>, beacon_state: &'a BeaconState<T>) -> Self {
        Self {
            roots: BlockRootsIterator::new(store, beacon_state),
        }
    }

    /// Create a new iterator over all blocks in the given `beacon_state` and prior states.
    pub fn owned(store: Arc<U>, beacon_state: BeaconState<T>) -> Self {
        Self {
            roots: BlockRootsIterator::owned(store, beacon_state),
        }
    }
}

impl<'a, T: EthSpec, U: Store<T>> Iterator for BlockIterator<'a, T, U> {
    type Item = BeaconBlock<T>;

    fn next(&mut self) -> Option<Self::Item> {
        let (root, _slot) = self.roots.next()?;
        self.roots.store.get(&root).ok()?
    }
}

/// Iterates backwards through block roots. If any specified slot is unable to be retrieved, the
/// iterator returns `None` indefinitely.
///
/// Uses the `block_roots` field of `BeaconState` to as the source of block roots and will
/// perform a lookup on the `Store` for a prior `BeaconState` if `block_roots` has been
/// exhausted.
///
/// Returns `None` for roots prior to genesis or when there is an error reading from `Store`.
pub struct BlockRootsIterator<'a, T: EthSpec, U> {
    store: Arc<U>,
    beacon_state: Cow<'a, BeaconState<T>>,
    slot: Slot,
}

impl<'a, T: EthSpec, U> Clone for BlockRootsIterator<'a, T, U> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            beacon_state: self.beacon_state.clone(),
            slot: self.slot,
        }
    }
}

impl<'a, T: EthSpec, U: Store<T>> BlockRootsIterator<'a, T, U> {
    /// Create a new iterator over all block roots in the given `beacon_state` and prior states.
    pub fn new(store: Arc<U>, beacon_state: &'a BeaconState<T>) -> Self {
        Self {
            store,
            slot: beacon_state.slot,
            beacon_state: Cow::Borrowed(beacon_state),
        }
    }

    /// Create a new iterator over all block roots in the given `beacon_state` and prior states.
    pub fn owned(store: Arc<U>, beacon_state: BeaconState<T>) -> Self {
        Self {
            store,
            slot: beacon_state.slot,
            beacon_state: Cow::Owned(beacon_state),
        }
    }
}

impl<'a, T: EthSpec, U: Store<T>> Iterator for BlockRootsIterator<'a, T, U> {
    type Item = (Hash256, Slot);

    fn next(&mut self) -> Option<Self::Item> {
        if self.slot == 0 || self.slot > self.beacon_state.slot {
            return None;
        }

        self.slot -= 1;

        match self.beacon_state.get_block_root(self.slot) {
            Ok(root) => Some((*root, self.slot)),
            Err(BeaconStateError::SlotOutOfBounds) => {
                // Read a `BeaconState` from the store that has access to prior historical roots.
                let beacon_state =
                    next_historical_root_backtrack_state(&*self.store, &self.beacon_state)?;

                self.beacon_state = Cow::Owned(beacon_state);

                let root = self.beacon_state.get_block_root(self.slot).ok()?;

                Some((*root, self.slot))
            }
            _ => None,
        }
    }
}

/// Fetch the next state to use whilst backtracking in `*RootsIterator`.
fn next_historical_root_backtrack_state<E: EthSpec, S: Store<E>>(
    store: &S,
    current_state: &BeaconState<E>,
) -> Option<BeaconState<E>> {
    // For compatibility with the freezer database's restore points, we load a state at
    // a restore point slot (thus avoiding replaying blocks). In the case where we're
    // not frozen, this just means we might not jump back by the maximum amount on
    // our first jump (i.e. at most 1 extra state load).
    let new_state_slot = slot_of_prev_restore_point::<E>(current_state.slot);
    let new_state_root = current_state.get_state_root(new_state_slot).ok()?;
    store.get_state(new_state_root, Some(new_state_slot)).ok()?
}

/// Compute the slot of the last guaranteed restore point in the freezer database.
fn slot_of_prev_restore_point<E: EthSpec>(current_slot: Slot) -> Slot {
    let slots_per_historical_root = E::SlotsPerHistoricalRoot::to_u64();
    (current_slot - 1) / slots_per_historical_root * slots_per_historical_root
}

pub type ReverseBlockRootIterator<'a, E, S> =
    ReverseHashAndSlotIterator<BlockRootsIterator<'a, E, S>>;
pub type ReverseStateRootIterator<'a, E, S> =
    ReverseHashAndSlotIterator<StateRootsIterator<'a, E, S>>;

pub type ReverseHashAndSlotIterator<I> = ReverseChainIterator<(Hash256, Slot), I>;

/// Provides a wrapper for an iterator that returns a given `T` before it starts returning results of
/// the `Iterator`.
pub struct ReverseChainIterator<T, I> {
    first_value_used: bool,
    first_value: T,
    iter: I,
}

impl<T, I> ReverseChainIterator<T, I>
where
    T: Sized,
    I: Iterator<Item = T> + Sized,
{
    pub fn new(first_value: T, iter: I) -> Self {
        Self {
            first_value_used: false,
            first_value,
            iter,
        }
    }
}

impl<T, I> Iterator for ReverseChainIterator<T, I>
where
    T: Clone,
    I: Iterator<Item = T>,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first_value_used {
            self.iter.next()
        } else {
            self.first_value_used = true;
            Some(self.first_value.clone())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::MemoryStore;
    use types::{test_utils::TestingBeaconStateBuilder, Keypair, MainnetEthSpec};

    fn get_state<T: EthSpec>() -> BeaconState<T> {
        let builder = TestingBeaconStateBuilder::from_single_keypair(
            0,
            &Keypair::random(),
            &T::default_spec(),
        );
        let (state, _keypairs) = builder.build();
        state
    }

    #[test]
    fn block_root_iter() {
        let store = Arc::new(MemoryStore::open());
        let slots_per_historical_root = MainnetEthSpec::slots_per_historical_root();

        let mut state_a: BeaconState<MainnetEthSpec> = get_state();
        let mut state_b: BeaconState<MainnetEthSpec> = get_state();

        state_a.slot = Slot::from(slots_per_historical_root);
        state_b.slot = Slot::from(slots_per_historical_root * 2);

        let mut hashes = (0..).map(Hash256::from_low_u64_be);

        for root in &mut state_a.block_roots[..] {
            *root = hashes.next().unwrap()
        }
        for root in &mut state_b.block_roots[..] {
            *root = hashes.next().unwrap()
        }

        let state_a_root = hashes.next().unwrap();
        state_b.state_roots[0] = state_a_root;
        store.put_state(&state_a_root, &state_a).unwrap();

        let iter = BlockRootsIterator::new(store.clone(), &state_b);

        assert!(
            iter.clone().any(|(_root, slot)| slot == 0),
            "iter should contain zero slot"
        );

        let mut collected: Vec<(Hash256, Slot)> = iter.collect();
        collected.reverse();

        let expected_len = 2 * MainnetEthSpec::slots_per_historical_root();

        assert_eq!(collected.len(), expected_len);

        for (i, item) in collected.iter().enumerate() {
            assert_eq!(item.0, Hash256::from_low_u64_be(i as u64));
        }
    }

    #[test]
    fn state_root_iter() {
        let store = Arc::new(MemoryStore::open());
        let slots_per_historical_root = MainnetEthSpec::slots_per_historical_root();

        let mut state_a: BeaconState<MainnetEthSpec> = get_state();
        let mut state_b: BeaconState<MainnetEthSpec> = get_state();

        state_a.slot = Slot::from(slots_per_historical_root);
        state_b.slot = Slot::from(slots_per_historical_root * 2);

        let mut hashes = (0..).map(Hash256::from_low_u64_be);

        for slot in 0..slots_per_historical_root {
            state_a
                .set_state_root(Slot::from(slot), hashes.next().unwrap())
                .unwrap_or_else(|_| panic!("should set state_a slot {}", slot));
        }
        for slot in slots_per_historical_root..slots_per_historical_root * 2 {
            state_b
                .set_state_root(Slot::from(slot), hashes.next().unwrap())
                .unwrap_or_else(|_| panic!("should set state_b slot {}", slot));
        }

        let state_a_root = Hash256::from_low_u64_be(slots_per_historical_root as u64);
        let state_b_root = Hash256::from_low_u64_be(slots_per_historical_root as u64 * 2);

        store.put_state(&state_a_root, &state_a).unwrap();
        store.put_state(&state_b_root, &state_b).unwrap();

        let iter = StateRootsIterator::new(store.clone(), &state_b);

        assert!(
            iter.clone().any(|(_root, slot)| slot == 0),
            "iter should contain zero slot"
        );

        let mut collected: Vec<(Hash256, Slot)> = iter.collect();
        collected.reverse();

        let expected_len = MainnetEthSpec::slots_per_historical_root() * 2;

        assert_eq!(collected.len(), expected_len, "collection length incorrect");

        for (i, item) in collected.iter().enumerate() {
            let (hash, slot) = *item;

            assert_eq!(slot, i as u64, "slot mismatch at {}: {} vs {}", i, slot, i);

            assert_eq!(
                hash,
                Hash256::from_low_u64_be(i as u64),
                "hash mismatch at {}",
                i
            );
        }
    }
}
