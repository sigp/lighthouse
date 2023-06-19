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
    pub fn simple_forwards_iterator(
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
            panic!("FIXME(sproul): better error")
        }
    }

    pub fn forwards_iter_block_roots_using_state(
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

    pub fn forwards_iter_state_roots_using_state(
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
}

/// Forwards root iterator that makes use of a flat field table in the freezer DB.
pub struct FrozenForwardsIterator<'a, E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    inner: ColumnIter<'a, Vec<u8>>,
    limit: Slot,
    finished: bool,
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
    ) -> Self {
        if column != DBColumn::BeaconBlockRoots && column != DBColumn::BeaconStateRoots {
            panic!("FIXME(sproul): bad column error");
        }
        let start = start_slot.as_u64().to_be_bytes();
        Self {
            inner: store.cold_db.iter_column_from(column, &start),
            limit: end_slot,
            finished: false,
            _phantom: PhantomData,
        }
    }
}

impl<'a, E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Iterator
    for FrozenForwardsIterator<'a, E, Hot, Cold>
{
    type Item = Result<(Hash256, Slot)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        self.inner
            .next()?
            .and_then(|(slot_bytes, root_bytes)| {
                if slot_bytes.len() != 8 || root_bytes.len() != 32 {
                    panic!("FIXME(sproul): put an error here")
                } else {
                    let slot = Slot::new(u64::from_be_bytes(slot_bytes.try_into().unwrap()));
                    let root = Hash256::from_slice(&root_bytes);

                    if slot + 1 == self.limit {
                        self.finished = true;
                    }
                    Ok(Some((root, slot)))
                }
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
        /// Data required by the `PostFinalization` iterator when we get to it.
        continuation_data: Option<Box<(BeaconState<E>, Hash256)>>,
        column: DBColumn,
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
}

impl<'a, E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>
    HybridForwardsIterator<'a, E, Hot, Cold>
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
        column: DBColumn,
        start_slot: Slot,
        end_slot: Option<Slot>,
        get_state: impl FnOnce() -> (BeaconState<E>, Hash256),
    ) -> Result<Self> {
        use HybridForwardsIterator::*;

        // FIXME(sproul): consider whether this is 100% correct
        let split_slot = store.get_split_slot();

        let result = if start_slot < split_slot {
            let iter = Box::new(FrozenForwardsIterator::new(
                store, column, start_slot, split_slot,
            ));

            // No continuation data is needed if the forwards iterator plans to halt before
            // `end_slot`. If it tries to continue further a `NoContinuationData` error will be
            // returned.
            let continuation_data = if end_slot.map_or(false, |end_slot| end_slot < split_slot) {
                None
            } else {
                Some(Box::new(get_state()))
            };
            PreFinalization {
                iter,
                store,
                continuation_data,
                column,
            }
        } else {
            PostFinalizationLazy {
                continuation_data: Some(Box::new(get_state())),
                store,
                start_slot,
                column,
            }
        };

        Ok(result)
    }

    fn do_next(&mut self) -> Result<Option<(Hash256, Slot)>> {
        use HybridForwardsIterator::*;

        match self {
            PreFinalization {
                iter,
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
                        let continuation_data = continuation_data.take();
                        let start_slot = Slot::from(iter.limit);

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
        }
    }
}

impl<'a, E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Iterator
    for HybridForwardsIterator<'a, E, Hot, Cold>
{
    type Item = Result<(Hash256, Slot)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.do_next().transpose()
    }
}
