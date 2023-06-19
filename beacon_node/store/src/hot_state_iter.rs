use crate::{hot_cold_store::HotColdDBError, Error, HotColdDB, HotStateSummary, ItemStore};
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

    fn do_next(&mut self) -> Result<Option<(Hash256, HotStateSummary)>, Error> {
        if self.next_state_root.is_zero() {
            return Ok(None);
        }

        let summary = self
            .store
            .load_hot_state_summary(&self.next_state_root)?
            .ok_or(HotColdDBError::MissingHotStateSummary(self.next_state_root))?;

        let state_root = self.next_state_root;

        self.next_state_root = summary.prev_state_root;
        self.next_slot -= 1;

        Ok(Some((state_root, summary)))
    }
}

impl<'a, E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Iterator
    for HotStateRootIter<'a, E, Hot, Cold>
{
    type Item = Result<(Hash256, HotStateSummary), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.do_next().transpose()
    }
}
