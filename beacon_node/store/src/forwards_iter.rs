use crate::chunked_iter::ChunkedVectorIter;
use crate::chunked_vector::{BlockRoots, StateRoots};
use crate::errors::{Error, Result};
use crate::iter::{BlockRootsIterator, StateRootsIterator};
use crate::{HotColdDB, ItemStore};
use itertools::process_results;
use std::sync::Arc;
use types::{BeaconState, ChainSpec, EthSpec, Hash256, Slot};

/// Forwards block roots iterator that makes use of the `block_roots` table in the freezer DB.
pub struct FrozenForwardsBlockRootsIterator<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    inner: ChunkedVectorIter<BlockRoots, E, Hot, Cold>,
}

/// Forwards block roots iterator that reverses a backwards iterator (only good for short ranges).
pub struct SimpleForwardsBlockRootsIterator {
    // Values from the backwards iterator (in slot descending order)
    values: Vec<(Hash256, Slot)>,
}

/// Fusion of the above two approaches to forwards iteration. Fast and efficient.
pub enum HybridForwardsBlockRootsIterator<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    PreFinalization {
        iter: Box<FrozenForwardsBlockRootsIterator<E, Hot, Cold>>,
        /// Data required by the `PostFinalization` iterator when we get to it.
        continuation_data: Box<Option<(BeaconState<E>, Hash256)>>,
    },
    PostFinalization {
        iter: SimpleForwardsBlockRootsIterator,
    },
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>
    FrozenForwardsBlockRootsIterator<E, Hot, Cold>
{
    pub fn new(
        store: Arc<HotColdDB<E, Hot, Cold>>,
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

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Iterator
    for FrozenForwardsBlockRootsIterator<E, Hot, Cold>
{
    type Item = (Hash256, Slot);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(|(slot, block_hash)| (block_hash, Slot::from(slot)))
    }
}

impl SimpleForwardsBlockRootsIterator {
    pub fn new<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
        store: Arc<HotColdDB<E, Hot, Cold>>,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_block_root: Hash256,
    ) -> Result<Self> {
        // Iterate backwards from the end state, stopping at the start slot.
        let values = process_results(
            std::iter::once(Ok((end_block_root, end_state.slot())))
                .chain(BlockRootsIterator::owned(store, end_state)),
            |iter| {
                iter.take_while(|(_, slot)| *slot >= start_slot)
                    .collect::<Vec<_>>()
            },
        )?;
        Ok(Self { values })
    }
}

impl Iterator for SimpleForwardsBlockRootsIterator {
    type Item = Result<(Hash256, Slot)>;

    fn next(&mut self) -> Option<Self::Item> {
        // Pop from the end of the vector to get the block roots in slot-ascending order.
        Ok(self.values.pop()).transpose()
    }
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>
    HybridForwardsBlockRootsIterator<E, Hot, Cold>
{
    pub fn new(
        store: Arc<HotColdDB<E, Hot, Cold>>,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_block_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<Self> {
        use HybridForwardsBlockRootsIterator::*;

        let latest_restore_point_slot = store.get_latest_restore_point_slot();

        let result = if start_slot < latest_restore_point_slot {
            PreFinalization {
                iter: Box::new(FrozenForwardsBlockRootsIterator::new(
                    store,
                    start_slot,
                    latest_restore_point_slot,
                    spec,
                )),
                continuation_data: Box::new(Some((end_state, end_block_root))),
            }
        } else {
            PostFinalization {
                iter: SimpleForwardsBlockRootsIterator::new(
                    store,
                    start_slot,
                    end_state,
                    end_block_root,
                )?,
            }
        };

        Ok(result)
    }

    fn do_next(&mut self) -> Result<Option<(Hash256, Slot)>> {
        use HybridForwardsBlockRootsIterator::*;

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
                        let (end_state, end_block_root) =
                            continuation_data.take().ok_or(Error::NoContinuationData)?;

                        *self = PostFinalization {
                            iter: SimpleForwardsBlockRootsIterator::new(
                                iter.inner.store.clone(),
                                Slot::from(iter.inner.end_vindex),
                                end_state,
                                end_block_root,
                            )?,
                        };
                        self.do_next()
                    }
                }
            }
            PostFinalization { iter } => iter.next().transpose(),
        }
    }
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Iterator
    for HybridForwardsBlockRootsIterator<E, Hot, Cold>
{
    type Item = Result<(Hash256, Slot)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.do_next().transpose()
    }
}

/// Forwards state roots iterator that makes use of the `state_roots` table in the freezer DB.
pub struct FrozenForwardsStateRootsIterator<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    inner: ChunkedVectorIter<StateRoots, E, Hot, Cold>,
}

/// Forwards state roots iterator that reverses a backwards iterator (only good for short ranges).
pub struct SimpleForwardsStateRootsIterator {
    // Values from the backwards iterator (in slot descending order)
    values: Vec<(Hash256, Slot)>,
}

/// Fusion of the above two approaches to forwards iteration. Fast and efficient.
pub enum HybridForwardsStateRootsIterator<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    PreFinalization {
        iter: Box<FrozenForwardsStateRootsIterator<E, Hot, Cold>>,
        /// Data required by the `PostFinalization` iterator when we get to it.
        continuation_data: Box<Option<(BeaconState<E>, Hash256)>>,
    },
    PostFinalization {
        iter: SimpleForwardsStateRootsIterator,
    },
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>
    FrozenForwardsStateRootsIterator<E, Hot, Cold>
{
    pub fn new(
        store: Arc<HotColdDB<E, Hot, Cold>>,
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

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Iterator
    for FrozenForwardsStateRootsIterator<E, Hot, Cold>
{
    type Item = (Hash256, Slot);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(|(slot, state_hash)| (state_hash, Slot::from(slot)))
    }
}

impl SimpleForwardsStateRootsIterator {
    pub fn new<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
        store: Arc<HotColdDB<E, Hot, Cold>>,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_state_root: Hash256,
    ) -> Result<Self> {
        // Iterate backwards from the end state, stopping at the start slot.
        let values = process_results(
            std::iter::once(Ok((end_state_root, end_state.slot())))
                .chain(StateRootsIterator::owned(store, end_state)),
            |iter| {
                iter.take_while(|(_, slot)| *slot >= start_slot)
                    .collect::<Vec<_>>()
            },
        )?;
        Ok(Self { values })
    }
}

impl Iterator for SimpleForwardsStateRootsIterator {
    type Item = Result<(Hash256, Slot)>;

    fn next(&mut self) -> Option<Self::Item> {
        // Pop from the end of the vector to get the state roots in slot-ascending order.
        Ok(self.values.pop()).transpose()
    }
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>
    HybridForwardsStateRootsIterator<E, Hot, Cold>
{
    pub fn new(
        store: Arc<HotColdDB<E, Hot, Cold>>,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_state_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<Self> {
        use HybridForwardsStateRootsIterator::*;

        let latest_restore_point_slot = store.get_latest_restore_point_slot();

        let result = if start_slot < latest_restore_point_slot {
            PreFinalization {
                iter: Box::new(FrozenForwardsStateRootsIterator::new(
                    store,
                    start_slot,
                    latest_restore_point_slot,
                    spec,
                )),
                continuation_data: Box::new(Some((end_state, end_state_root))),
            }
        } else {
            PostFinalization {
                iter: SimpleForwardsStateRootsIterator::new(
                    store,
                    start_slot,
                    end_state,
                    end_state_root,
                )?,
            }
        };

        Ok(result)
    }

    fn do_next(&mut self) -> Result<Option<(Hash256, Slot)>> {
        use HybridForwardsStateRootsIterator::*;

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
                        let (end_state, end_state_root) =
                            continuation_data.take().ok_or(Error::NoContinuationData)?;

                        *self = PostFinalization {
                            iter: SimpleForwardsStateRootsIterator::new(
                                iter.inner.store.clone(),
                                Slot::from(iter.inner.end_vindex),
                                end_state,
                                end_state_root,
                            )?,
                        };
                        self.do_next()
                    }
                }
            }
            PostFinalization { iter } => iter.next().transpose(),
        }
    }
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Iterator
    for HybridForwardsStateRootsIterator<E, Hot, Cold>
{
    type Item = Result<(Hash256, Slot)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.do_next().transpose()
    }
}
