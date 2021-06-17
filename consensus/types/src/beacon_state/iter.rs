use crate::*;

/// Returns an iterator across the past block roots of `state` in descending slot-order.
///
/// The iterator has the following characteristics:
///
/// - Will only return *at most* `state.block_roots().len()` entries.
/// - Will not return slots prior to the genesis_slot.
/// - Each call to next will result in a slot one less than the prior one (or `None`).
/// - Skipped slots will contain the block root from the prior non-skipped slot.
pub struct BlockRootsIter<'a, T: EthSpec> {
    state: &'a BeaconState<T>,
    genesis_slot: Slot,
    prev: Slot,
}

impl<'a, T: EthSpec> BlockRootsIter<'a, T> {
    /// Instantiates a new iterator, returning roots for slots earlier that `state.slot`.
    ///
    /// See the struct-level documentation for more details.
    pub fn new(state: &'a BeaconState<T>, genesis_slot: Slot) -> Self {
        Self {
            state,
            genesis_slot,
            prev: state.slot(),
        }
    }
}

impl<'a, T: EthSpec> Iterator for BlockRootsIter<'a, T> {
    type Item = Result<(Slot, Hash256), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.prev > self.genesis_slot
            && self.prev
                > self
                    .state
                    .slot()
                    .saturating_sub(self.state.block_roots().len() as u64)
        {
            self.prev = self.prev.saturating_sub(1_u64);
            Some(
                self.state
                    .get_block_root(self.prev)
                    .map(|root| (self.prev, *root)),
            )
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use crate::*;

    type E = MinimalEthSpec;

    fn root_slot(i: usize) -> (Slot, Hash256) {
        (Slot::from(i), Hash256::from_low_u64_be(i as u64))
    }

    fn all_roots(state: &BeaconState<E>, spec: &ChainSpec) -> Vec<(Slot, Hash256)> {
        state
            .rev_iter_block_roots(spec)
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn block_roots_iter() {
        let spec = E::default_spec();

        let mut state: BeaconState<E> = BeaconState::new(0, <_>::default(), &spec);

        for i in 0..state.block_roots().len() {
            state.block_roots_mut()[i] = root_slot(i).1;
        }

        assert_eq!(
            state.slot(),
            spec.genesis_slot,
            "test assume a genesis slot state"
        );
        assert_eq!(
            all_roots(&state, &spec),
            vec![],
            "state at genesis slot has no history"
        );

        *state.slot_mut() = Slot::new(1);
        assert_eq!(
            all_roots(&state, &spec),
            vec![root_slot(0)],
            "first slot after genesis has one slot history"
        );

        *state.slot_mut() = Slot::new(2);
        assert_eq!(
            all_roots(&state, &spec),
            vec![root_slot(1), root_slot(0)],
            "second slot after genesis has two slot history"
        );

        *state.slot_mut() = Slot::from(state.block_roots().len() + 2);
        let expected = (2..state.block_roots().len() + 2)
            .rev()
            .map(|i| (Slot::from(i), *state.get_block_root(Slot::from(i)).unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(
            all_roots(&state, &spec),
            expected,
            "slot higher than the block roots history"
        );
    }

    #[test]
    fn block_roots_iter_non_zero_genesis() {
        let mut spec = E::default_spec();
        spec.genesis_slot = Slot::new(4);

        let mut state: BeaconState<E> = BeaconState::new(0, <_>::default(), &spec);

        for i in 0..state.block_roots().len() {
            state.block_roots_mut()[i] = root_slot(i).1;
        }

        assert_eq!(
            state.slot(),
            spec.genesis_slot,
            "test assume a genesis slot state"
        );
        assert_eq!(
            all_roots(&state, &spec),
            vec![],
            "state at genesis slot has no history"
        );

        *state.slot_mut() = Slot::new(5);
        assert_eq!(
            all_roots(&state, &spec),
            vec![root_slot(4)],
            "first slot after genesis has one slot history"
        );

        *state.slot_mut() = Slot::new(6);
        assert_eq!(
            all_roots(&state, &spec),
            vec![root_slot(5), root_slot(4)],
            "second slot after genesis has two slot history"
        );
    }
}
