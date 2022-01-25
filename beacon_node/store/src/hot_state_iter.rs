use crate::{hot_cold_store::HotColdDBError, Error, HotColdDB, ItemStore};
use itertools::process_results;
use std::iter;
use take_until::TakeUntilExt;
use types::{EthSpec, Hash256, Slot};

pub struct HotStateRootIter<'a, E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    store: &'a HotColdDB<E, Hot, Cold>,
    next_slot: Slot,
    next_state_root: Hash256,
}

impl<'a, E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> HotStateRootIter<'a, E, Hot, Cold> {
    pub fn new(
        store: &'a HotColdDB<E, Hot, Cold>,
        next_slot: Slot,
        next_state_root: Hash256,
    ) -> Self {
        Self {
            store,
            next_slot,
            next_state_root,
        }
    }

    fn do_next(&mut self) -> Result<Option<(Hash256, Slot)>, Error> {
        if self.next_state_root.is_zero() {
            return Ok(None);
        }

        let summary = self
            .store
            .load_hot_state_summary(&self.next_state_root)?
            .ok_or_else(|| HotColdDBError::MissingHotStateSummary(self.next_state_root))?;

        let slot = self.next_slot;
        let state_root = self.next_state_root;

        self.next_state_root = summary.prev_state_root;
        self.next_slot -= 1;

        Ok(Some((state_root, slot)))
    }
}

impl<'a, E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Iterator
    for HotStateRootIter<'a, E, Hot, Cold>
{
    type Item = Result<(Hash256, Slot), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.do_next().transpose()
    }
}

pub struct ForwardsHotStateRootIter {
    // Values from the backwards iterator (in slot descending order)
    values: Vec<(Hash256, Slot)>,
}

impl ForwardsHotStateRootIter {
    pub fn new<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
        store: &HotColdDB<E, Hot, Cold>,
        start_slot: Slot,
        end_slot: Slot,
        last_state_root: Hash256,
        second_last_state_root: Hash256,
    ) -> Result<Self, Error> {
        process_results(
            iter::once(Ok((last_state_root, end_slot))).chain(HotStateRootIter::new(
                store,
                end_slot - 1,
                second_last_state_root,
            )),
            |iter| {
                let values = iter.take_until(|(_, slot)| *slot == start_slot).collect();
                Self { values }
            },
        )
    }
}

impl Iterator for ForwardsHotStateRootIter {
    type Item = Result<(Hash256, Slot), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        // Pop from the end of the vector to get the state roots in slot-ascending order.
        Ok(self.values.pop()).transpose()
    }
}
