use crate::chunked_iter::ChunkedVectorIter;
use crate::chunked_vector::{BlockRoots, Field, StateRoots};
use crate::errors::{Error, Result};
use crate::iter::{BlockRootsIterator, StateRootsIterator};
use crate::{HotColdDB, ItemStore};
use itertools::process_results;
use types::{BeaconState, ChainSpec, EthSpec, Hash256, Slot};

pub type HybridForwardsBlockRootsIterator<'a, E, Hot, Cold> =
    HybridForwardsIterator<'a, E, BlockRoots, Hot, Cold>;
pub type HybridForwardsStateRootsIterator<'a, E, Hot, Cold> =
    HybridForwardsIterator<'a, E, StateRoots, Hot, Cold>;

/// Trait unifying `BlockRoots` and `StateRoots` for forward iteration.
pub trait Root<E: EthSpec>: Field<E, Value = Hash256> {
    fn simple_forwards_iterator<Hot: ItemStore<E>, Cold: ItemStore<E>>(
        store: &HotColdDB<E, Hot, Cold>,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_root: Hash256,
    ) -> Result<SimpleForwardsIterator>;
}

impl<E: EthSpec> Root<E> for BlockRoots {
    fn simple_forwards_iterator<Hot: ItemStore<E>, Cold: ItemStore<E>>(
        store: &HotColdDB<E, Hot, Cold>,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_block_root: Hash256,
    ) -> Result<SimpleForwardsIterator> {
        // Iterate backwards from the end state, stopping at the start slot.
        let values = process_results(
            std::iter::once(Ok((end_block_root, end_state.slot())))
                .chain(BlockRootsIterator::owned(store, end_state)),
            |iter| {
                iter.take_while(|(_, slot)| *slot >= start_slot)
                    .collect::<Vec<_>>()
            },
        )?;
        Ok(SimpleForwardsIterator { values })
    }
}

impl<E: EthSpec> Root<E> for StateRoots {
    fn simple_forwards_iterator<Hot: ItemStore<E>, Cold: ItemStore<E>>(
        store: &HotColdDB<E, Hot, Cold>,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_state_root: Hash256,
    ) -> Result<SimpleForwardsIterator> {
        // Iterate backwards from the end state, stopping at the start slot.
        let values = process_results(
            std::iter::once(Ok((end_state_root, end_state.slot())))
                .chain(StateRootsIterator::owned(store, end_state)),
            |iter| {
                iter.take_while(|(_, slot)| *slot >= start_slot)
                    .collect::<Vec<_>>()
            },
        )?;
        Ok(SimpleForwardsIterator { values })
    }
}

/// Forwards root iterator that makes use of a flat field table in the freezer DB.
pub struct FrozenForwardsIterator<'a, E: EthSpec, F: Root<E>, Hot: ItemStore<E>, Cold: ItemStore<E>>
{
    inner: ChunkedVectorIter<'a, F, E, Hot, Cold>,
}

impl<'a, E: EthSpec, F: Root<E>, Hot: ItemStore<E>, Cold: ItemStore<E>>
    FrozenForwardsIterator<'a, E, F, Hot, Cold>
{
    pub fn new(
        store: &'a HotColdDB<E, Hot, Cold>,
        start_slot: Slot,
        last_restore_point_slot: Slot,
        spec: &ChainSpec,
    ) -> Self {
        Self {
            inner: ChunkedVectorIter::new(
                store,
                start_slot.as_usize(),
                last_restore_point_slot,
                spec,
            ),
        }
    }
}

impl<'a, E: EthSpec, F: Root<E>, Hot: ItemStore<E>, Cold: ItemStore<E>> Iterator
    for FrozenForwardsIterator<'a, E, F, Hot, Cold>
{
    type Item = (Hash256, Slot);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(|(slot, root)| (root, Slot::from(slot)))
    }
}

/// Forwards root iterator that reverses a backwards iterator (only good for short ranges).
pub struct SimpleForwardsIterator {
    // Values from the backwards iterator (in slot descending order)
    values: Vec<(Hash256, Slot)>,
}

impl Iterator for SimpleForwardsIterator {
    type Item = Result<(Hash256, Slot)>;

    fn next(&mut self) -> Option<Self::Item> {
        // Pop from the end of the vector to get the state roots in slot-ascending order.
        Ok(self.values.pop()).transpose()
    }
}

/// Fusion of the above two approaches to forwards iteration. Fast and efficient.
pub enum HybridForwardsIterator<'a, E: EthSpec, F: Root<E>, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    PreFinalization {
        iter: Box<FrozenForwardsIterator<'a, E, F, Hot, Cold>>,
        /// Data required by the `PostFinalization` iterator when we get to it.
        continuation_data: Option<Box<(BeaconState<E>, Hash256)>>,
    },
    PostFinalizationLazy {
        continuation_data: Option<Box<(BeaconState<E>, Hash256)>>,
        store: &'a HotColdDB<E, Hot, Cold>,
        start_slot: Slot,
    },
    PostFinalization {
        iter: SimpleForwardsIterator,
    },
}

impl<'a, E: EthSpec, F: Root<E>, Hot: ItemStore<E>, Cold: ItemStore<E>>
    HybridForwardsIterator<'a, E, F, Hot, Cold>
{
    /// Construct a new hybrid iterator.
    ///
    /// The `get_state` closure should return a beacon state and final block/state root to backtrack
    /// from in the case where the iterated range does not lie entirely within the frozen portion of
    /// the database. If an `end_slot` is provided and it is before the database's latest restore
    /// point slot then the `get_state` closure will not be called at all.
    ///
    /// It is OK for `get_state` to hold a lock while this function is evaluated, as the returned
    /// iterator is as lazy as possible and won't do any work apart from calling `get_state`.
    ///
    /// Conversely, if `get_state` does extensive work (e.g. loading data from disk) then this
    /// function may block for some time while `get_state` runs.
    pub fn new(
        store: &'a HotColdDB<E, Hot, Cold>,
        start_slot: Slot,
        end_slot: Option<Slot>,
        get_state: impl FnOnce() -> Result<(BeaconState<E>, Hash256)>,
        spec: &ChainSpec,
    ) -> Result<Self> {
        use HybridForwardsIterator::*;

        let latest_restore_point_slot = store.get_latest_restore_point_slot();

        let result = if start_slot < latest_restore_point_slot {
            let iter = Box::new(FrozenForwardsIterator::new(
                store,
                start_slot,
                latest_restore_point_slot,
                spec,
            ));

            // No continuation data is needed if the forwards iterator plans to halt before
            // `end_slot`. If it tries to continue further a `NoContinuationData` error will be
            // returned.
            let continuation_data =
                if end_slot.map_or(false, |end_slot| end_slot < latest_restore_point_slot) {
                    None
                } else {
                    Some(Box::new(get_state()?))
                };
            PreFinalization {
                iter,
                continuation_data,
            }
        } else {
            PostFinalizationLazy {
                continuation_data: Some(Box::new(get_state()?)),
                store,
                start_slot,
            }
        };

        Ok(result)
    }

    fn do_next(&mut self) -> Result<Option<(Hash256, Slot)>> {
        use HybridForwardsIterator::*;

        match self {
            PreFinalization {
                iter,
                continuation_data,
            } => {
                match iter.next() {
                    Some(x) => Ok(Some(x)),
                    // Once the pre-finalization iterator is consumed, transition
                    // to a post-finalization iterator beginning from the last slot
                    // of the pre iterator.
                    None => {
                        let continuation_data = continuation_data.take();
                        let store = iter.inner.store;
                        let start_slot = Slot::from(iter.inner.end_vindex);

                        *self = PostFinalizationLazy {
                            continuation_data,
                            store,
                            start_slot,
                        };

                        self.do_next()
                    }
                }
            }
            PostFinalizationLazy {
                continuation_data,
                store,
                start_slot,
            } => {
                let (end_state, end_root) =
                    *continuation_data.take().ok_or(Error::NoContinuationData)?;
                *self = PostFinalization {
                    iter: F::simple_forwards_iterator(store, *start_slot, end_state, end_root)?,
                };
                self.do_next()
            }
            PostFinalization { iter } => iter.next().transpose(),
        }
    }
}

impl<'a, E: EthSpec, F: Root<E>, Hot: ItemStore<E>, Cold: ItemStore<E>> Iterator
    for HybridForwardsIterator<'a, E, F, Hot, Cold>
{
    type Item = Result<(Hash256, Slot)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.do_next().transpose()
    }
}
