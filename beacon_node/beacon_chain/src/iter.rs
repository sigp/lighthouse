use std::sync::Arc;
use store::Store;
use types::{BeaconState, BeaconStateError, EthSpec, Hash256, Slot};

/// Iterates backwards through block roots.
///
/// Uses the `latest_block_roots` field of `BeaconState` to as the source of block roots and will
/// perform a lookup on the `Store` for a prior `BeaconState` if `latest_block_roots` has been
/// exhausted.
///
/// Returns `None` for roots prior to genesis or when there is an error reading from `Store`.
pub struct BlockRootsIterator<T: EthSpec, U> {
    store: Arc<U>,
    beacon_state: BeaconState<T>,
    slot: Slot,
}

impl<T: EthSpec, U: Store> BlockRootsIterator<T, U> {
    /// Create a new iterator over all block roots in the given `beacon_state` and prior states.
    pub fn from_state(store: Arc<U>, beacon_state: BeaconState<T>) -> Self {
        Self {
            slot: beacon_state.slot,
            beacon_state,
            store,
        }
    }
}

impl<T: EthSpec, U: Store> Iterator for BlockRootsIterator<T, U> {
    type Item = Hash256;

    fn next(&mut self) -> Option<Self::Item> {
        if self.slot == 0 {
            return None;
        }

        let slot = self.slot - 1;

        match self.beacon_state.get_block_root(slot) {
            Ok(root) => Some(*root),
            Err(BeaconStateError::SlotOutOfBounds) => {
                // Read a `BeaconState` from the store that has access to prior historical root.
                self.beacon_state = {
                    // Read the earliest historic state in the current slot.
                    let earliest_historic_slot =
                        self.beacon_state.slot - Slot::from(T::slots_per_historical_root());

                    // Load the earlier state from disk.
                    let new_state_root = self
                        .beacon_state
                        .get_state_root(earliest_historic_slot)
                        .ok()?;

                    let state_option = self.store.get(&new_state_root).ok()?;
                    state_option?
                };

                self.beacon_state.get_block_root(slot).ok().cloned()
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use store::MemoryStore;
    use types::{test_utils::TestingBeaconStateBuilder, FoundationEthSpec, Keypair};

    fn get_state<T: EthSpec>() -> BeaconState<T> {
        let builder =
            TestingBeaconStateBuilder::from_single_keypair(0, &Keypair::random(), &T::spec());
        let (state, _keypairs) = builder.build();
        state
    }

    #[test]
    fn root_iter() {
        let store = Arc::new(MemoryStore::open());

        let mut state_a: BeaconState<FoundationEthSpec> = get_state();
        let mut state_b: BeaconState<FoundationEthSpec> = get_state();

        let mut hashes = (0..).into_iter().map(|i| Hash256::from(i));

        for root in &mut state_a.latest_block_roots[..] {
            *root = hashes.next().unwrap()
        }
        for root in &mut state_b.latest_block_roots[..] {
            *root = hashes.next().unwrap()
        }

        let state_a_root = hashes.next().unwrap();
        state_b.latest_state_roots[0] = state_a_root;
        store.put(&state_a_root, &state_a).unwrap();

        let iter = BlockRootsIterator::from_state(store.clone(), state_b.clone());
        let mut collected: Vec<Hash256> = iter.collect();
        collected.reverse();

        for (i, item) in collected.iter().enumerate() {
            assert_eq!(*item, Hash256::from(i as u64));
        }
    }
}
