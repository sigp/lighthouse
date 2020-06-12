use crate::{Error, HotColdDB, HotStateSummary, ItemStore};
use types::{BeaconState, EthSpec, Hash256};

/// A collection of states to be stored in the database.
///
/// Consumes minimal space in memory by not storing states between epoch boundaries.
#[derive(Debug, Clone, Default)]
pub struct StateBatch<E: EthSpec> {
    items: Vec<BatchItem<E>>,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum BatchItem<E: EthSpec> {
    Full(Hash256, BeaconState<E>),
    Summary(Hash256, HotStateSummary),
}

impl<E: EthSpec> StateBatch<E> {
    /// Create a new empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stage a `BeaconState` to be stored.
    pub fn add_state(&mut self, state_root: Hash256, state: &BeaconState<E>) -> Result<(), Error> {
        let item = if state.slot % E::slots_per_epoch() == 0 {
            BatchItem::Full(state_root, state.clone())
        } else {
            BatchItem::Summary(state_root, HotStateSummary::new(&state_root, state)?)
        };
        self.items.push(item);
        Ok(())
    }

    /// Write the batch to the database.
    ///
    /// May fail to write the full batch if any of the items error (i.e. not atomic!)
    pub fn commit<Hot: ItemStore<E>, Cold: ItemStore<E>>(
        self,
        store: &HotColdDB<E, Hot, Cold>,
    ) -> Result<(), Error> {
        self.items.into_iter().try_for_each(|item| match item {
            BatchItem::Full(state_root, state) => store.put_state(&state_root, &state),
            BatchItem::Summary(state_root, summary) => {
                store.put_state_summary(&state_root, summary)
            }
        })
    }
}
