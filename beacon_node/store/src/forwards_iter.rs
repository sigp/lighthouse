use crate::errors::{Error, Result};
use crate::iter::{BlockRootsIterator, StateRootsIterator};
use crate::{ColumnIter, DBColumn, HotColdDB, ItemStore};
use itertools::process_results;
use std::marker::PhantomData;
use types::{BeaconState, EthSpec, Hash256, Slot};

pub type HybridForwardsBlockRootsIterator<'a, E, Hot, Cold> =
    HybridForwardsIterator<'a, E, Hot, Cold>;
pub type HybridForwardsStateRootsIterator<'a, E, Hot, Cold> =
    HybridForwardsIterator<'a, E, Hot, Cold>;

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> HotColdDB<E, Hot, Cold> {
    fn simple_forwards_iterator(
        &self,
        column: DBColumn,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_root: Hash256,
    ) -> Result<SimpleForwardsIterator> {
        if column == DBColumn::BeaconBlockRoots {
            self.forwards_iter_block_roots_using_state(start_slot, end_state, end_root)
        } else if column == DBColumn::BeaconStateRoots {
            self.forwards_iter_state_roots_using_state(start_slot, end_state, end_root)
        } else {
            Err(Error::ForwardsIterInvalidColumn(column))
        }
    }

    fn forwards_iter_block_roots_using_state(
        &self,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_block_root: Hash256,
    ) -> Result<SimpleForwardsIterator> {
        // Iterate backwards from the end state, stopping at the start slot.
        let values = process_results(
            std::iter::once(Ok((end_block_root, end_state.slot())))
                .chain(BlockRootsIterator::owned(self, end_state)),
            |iter| {
                iter.take_while(|(_, slot)| *slot >= start_slot)
                    .collect::<Vec<_>>()
            },
        )?;
        Ok(SimpleForwardsIterator { values })
    }

    fn forwards_iter_state_roots_using_state(
        &self,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_state_root: Hash256,
    ) -> Result<SimpleForwardsIterator> {
        // Iterate backwards from the end state, stopping at the start slot.
        let values = process_results(
            std::iter::once(Ok((end_state_root, end_state.slot())))
                .chain(StateRootsIterator::owned(self, end_state)),
            |iter| {
                iter.take_while(|(_, slot)| *slot >= start_slot)
                    .collect::<Vec<_>>()
            },
        )?;
        Ok(SimpleForwardsIterator { values })
    }

    /// Values in `column` are available in the range `start_slot..upper_bound`.
    ///
    /// If `None` is returned then no values are available from `start_slot` due to pruning or
    /// incomplete backfill.
    pub fn freezer_upper_bound_for_column(
        &self,
        column: DBColumn,
        start_slot: Slot,
    ) -> Result<Option<Slot>> {
        if column == DBColumn::BeaconBlockRoots {
            Ok(self.freezer_upper_bound_for_block_roots(start_slot))
        } else if column == DBColumn::BeaconStateRoots {
            Ok(self.freezer_upper_bound_for_state_roots(start_slot))
        } else {
            Err(Error::ForwardsIterInvalidColumn(column))
        }
    }

    fn freezer_upper_bound_for_block_roots(&self, start_slot: Slot) -> Option<Slot> {
        let oldest_block_slot = self.get_oldest_block_slot();
        if start_slot < oldest_block_slot {
            if start_slot == 0 {
                // Slot 0 block root is always available.
                Some(Slot::new(1))
                // Non-zero block roots are not available prior to the `oldest_block_slot`.
            } else {
                None
            }
        } else {
            // Block roots are stored for all slots up to the split slot (exclusive).
            Some(self.get_split_slot())
        }
    }

    fn freezer_upper_bound_for_state_roots(&self, start_slot: Slot) -> Option<Slot> {
        let split_slot = self.get_split_slot();
        let anchor = self.get_anchor_info();

        if start_slot >= anchor.state_upper_limit {
            // Starting slot is after the upper limit, so the split is the upper limit.
            // The split state's root is not available in the freezer so this is exclusive.
            Some(split_slot)
        } else if start_slot <= anchor.state_lower_limit {
            // Starting slot is prior to lower limit, so that's the upper limit. We can't
            // iterate past the lower limit into the gap. The +1 accounts for exclusivity.
            Some(anchor.state_lower_limit + 1)
        } else {
            // In the gap, nothing is available.
            None
        }
    }
}

/// Forwards root iterator that makes use of a slot -> root mapping in the freezer DB.
pub struct FrozenForwardsIterator<'a, E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    inner: ColumnIter<'a, Vec<u8>>,
    column: DBColumn,
    next_slot: Slot,
    end_slot: Slot,
    _phantom: PhantomData<(E, Hot, Cold)>,
}

impl<'a, E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>
    FrozenForwardsIterator<'a, E, Hot, Cold>
{
    /// `end_slot` is EXCLUSIVE here.
    pub fn new(
        store: &'a HotColdDB<E, Hot, Cold>,
        column: DBColumn,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<Self> {
        if column != DBColumn::BeaconBlockRoots && column != DBColumn::BeaconStateRoots {
            return Err(Error::ForwardsIterInvalidColumn(column));
        }
        let start = start_slot.as_u64().to_be_bytes();
        Ok(Self {
            inner: store.cold_db.iter_column_from(column, &start),
            column,
            next_slot: start_slot,
            end_slot,
            _phantom: PhantomData,
        })
    }
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Iterator
    for FrozenForwardsIterator<'_, E, Hot, Cold>
{
    type Item = Result<(Hash256, Slot)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_slot == self.end_slot {
            return None;
        }
        self.inner
            .next()?
            .and_then(|(slot_bytes, root_bytes)| {
                let slot = slot_bytes
                    .clone()
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map(Slot::new)
                    .map_err(|_| Error::InvalidBytes)?;
                if root_bytes.len() != std::mem::size_of::<Hash256>() {
                    return Err(Error::InvalidBytes);
                }
                let root = Hash256::from_slice(&root_bytes);

                if slot != self.next_slot {
                    return Err(Error::ForwardsIterGap(self.column, slot, self.next_slot));
                }
                self.next_slot += 1;

                Ok(Some((root, slot)))
            })
            .transpose()
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
pub enum HybridForwardsIterator<'a, E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    PreFinalization {
        iter: Box<FrozenForwardsIterator<'a, E, Hot, Cold>>,
        store: &'a HotColdDB<E, Hot, Cold>,
        end_slot: Option<Slot>,
        column: DBColumn,
        /// Data required by the `PostFinalization` iterator when we get to it.
        continuation_data: Option<Box<(BeaconState<E>, Hash256)>>,
    },
    PostFinalizationLazy {
        continuation_data: Option<Box<(BeaconState<E>, Hash256)>>,
        store: &'a HotColdDB<E, Hot, Cold>,
        start_slot: Slot,
        column: DBColumn,
    },
    PostFinalization {
        iter: SimpleForwardsIterator,
    },
    Finished,
}

impl<'a, E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>
    HybridForwardsIterator<'a, E, Hot, Cold>
{
    /// Construct a new hybrid iterator.
    ///
    /// The `get_state` closure should return a beacon state and final block/state root to backtrack
    /// from in the case where the iterated range does not lie entirely within the frozen portion of
    /// the database. If an `end_slot` is provided and it is before the database's freezer upper
    /// limit for the field then the `get_state` closure will not be called at all.
    ///
    /// It is OK for `get_state` to hold a lock while this function is evaluated, as the returned
    /// iterator is as lazy as possible and won't do any work apart from calling `get_state`.
    ///
    /// Conversely, if `get_state` does extensive work (e.g. loading data from disk) then this
    /// function may block for some time while `get_state` runs.
    pub fn new(
        store: &'a HotColdDB<E, Hot, Cold>,
        column: DBColumn,
        start_slot: Slot,
        end_slot: Option<Slot>,
        get_state: impl FnOnce() -> Result<(BeaconState<E>, Hash256)>,
    ) -> Result<Self> {
        use HybridForwardsIterator::*;

        // First slot at which this field is *not* available in the freezer. i.e. all slots less
        // than this slot have their data available in the freezer.
        let opt_freezer_upper_bound = store.freezer_upper_bound_for_column(column, start_slot)?;

        match opt_freezer_upper_bound {
            Some(freezer_upper_bound) if start_slot < freezer_upper_bound => {
                // EXCLUSIVE end slot for the frozen portion of the iterator.
                let frozen_end_slot = end_slot.map_or(freezer_upper_bound, |end_slot| {
                    std::cmp::min(end_slot + 1, freezer_upper_bound)
                });
                let iter = Box::new(FrozenForwardsIterator::new(
                    store,
                    column,
                    start_slot,
                    frozen_end_slot,
                )?);

                // No continuation data is needed if the forwards iterator plans to halt before
                // `end_slot`. If it tries to continue further a `NoContinuationData` error will be
                // returned.
                let continuation_data =
                    if end_slot.map_or(false, |end_slot| end_slot < freezer_upper_bound) {
                        None
                    } else {
                        Some(Box::new(get_state()?))
                    };
                Ok(PreFinalization {
                    iter,
                    store,
                    end_slot,
                    column,
                    continuation_data,
                })
            }
            _ => Ok(PostFinalizationLazy {
                continuation_data: Some(Box::new(get_state()?)),
                store,
                start_slot,
                column,
            }),
        }
    }

    fn do_next(&mut self) -> Result<Option<(Hash256, Slot)>> {
        use HybridForwardsIterator::*;

        match self {
            PreFinalization {
                iter,
                end_slot,
                store,
                continuation_data,
                column,
            } => {
                match iter.next() {
                    Some(x) => x.map(Some),
                    // Once the pre-finalization iterator is consumed, transition
                    // to a post-finalization iterator beginning from the last slot
                    // of the pre iterator.
                    None => {
                        // If the iterator has an end slot (inclusive) which has already been
                        // covered by the (exclusive) frozen forwards iterator, then we're done!
                        if end_slot.map_or(false, |end_slot| iter.end_slot == end_slot + 1) {
                            *self = Finished;
                            return Ok(None);
                        }

                        let continuation_data = continuation_data.take();
                        let start_slot = iter.end_slot;

                        *self = PostFinalizationLazy {
                            continuation_data,
                            store,
                            start_slot,
                            column: *column,
                        };

                        self.do_next()
                    }
                }
            }
            PostFinalizationLazy {
                continuation_data,
                store,
                start_slot,
                column,
            } => {
                let (end_state, end_root) =
                    *continuation_data.take().ok_or(Error::NoContinuationData)?;
                *self = PostFinalization {
                    iter: store.simple_forwards_iterator(
                        *column,
                        *start_slot,
                        end_state,
                        end_root,
                    )?,
                };
                self.do_next()
            }
            PostFinalization { iter } => iter.next().transpose(),
            Finished => Ok(None),
        }
    }
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Iterator
    for HybridForwardsIterator<'_, E, Hot, Cold>
{
    type Item = Result<(Hash256, Slot)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.do_next().transpose()
    }
}
