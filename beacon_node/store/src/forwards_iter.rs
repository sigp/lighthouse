use crate::chunked_iter::ChunkedVectorIter;
use crate::chunked_vector::BlockRoots;
use crate::iter::{BlockRootsIterator, ReverseBlockRootIterator};
use crate::{DiskStore, Store};
use slog::error;
use std::sync::Arc;
use types::{BeaconState, ChainSpec, EthSpec, Hash256, Slot};

/// Forwards block roots iterator that makes use of the `block_roots` table in the freezer DB.
pub struct FrozenForwardsBlockRootsIterator<E: EthSpec> {
    inner: ChunkedVectorIter<BlockRoots, E>,
}

/// Forwards block roots iterator that reverses a backwards iterator (only good for short ranges).
pub struct SimpleForwardsBlockRootsIterator {
    // Values from the backwards iterator (in slot descending order)
    values: Vec<(Hash256, Slot)>,
}

/// Fusion of the above two approaches to forwards iteration. Fast and efficient.
pub enum HybridForwardsBlockRootsIterator<E: EthSpec> {
    PreFinalization {
        iter: Box<FrozenForwardsBlockRootsIterator<E>>,
        /// Data required by the `PostFinalization` iterator when we get to it.
        continuation_data: Box<Option<(BeaconState<E>, Hash256)>>,
    },
    PostFinalization {
        iter: SimpleForwardsBlockRootsIterator,
    },
}

impl<E: EthSpec> FrozenForwardsBlockRootsIterator<E> {
    pub fn new(
        store: Arc<DiskStore<E>>,
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

impl<E: EthSpec> Iterator for FrozenForwardsBlockRootsIterator<E> {
    type Item = (Hash256, Slot);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(|(slot, block_hash)| (block_hash, Slot::from(slot)))
    }
}

impl SimpleForwardsBlockRootsIterator {
    pub fn new<S: Store<E>, E: EthSpec>(
        store: Arc<S>,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_block_root: Hash256,
    ) -> Self {
        // Iterate backwards from the end state, stopping at the start slot.
        Self {
            values: ReverseBlockRootIterator::new(
                (end_block_root, end_state.slot),
                BlockRootsIterator::owned(store, end_state),
            )
            .take_while(|(_, slot)| *slot >= start_slot)
            .collect(),
        }
    }
}

impl Iterator for SimpleForwardsBlockRootsIterator {
    type Item = (Hash256, Slot);

    fn next(&mut self) -> Option<Self::Item> {
        // Pop from the end of the vector to get the block roots in slot-ascending order.
        self.values.pop()
    }
}

impl<E: EthSpec> HybridForwardsBlockRootsIterator<E> {
    pub fn new(
        store: Arc<DiskStore<E>>,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_block_root: Hash256,
        spec: &ChainSpec,
    ) -> Self {
        use HybridForwardsBlockRootsIterator::*;

        let latest_restore_point_slot = store.get_latest_restore_point_slot();

        if start_slot < latest_restore_point_slot {
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
                ),
            }
        }
    }
}

impl<E: EthSpec> Iterator for HybridForwardsBlockRootsIterator<E> {
    type Item = (Hash256, Slot);

    fn next(&mut self) -> Option<Self::Item> {
        use HybridForwardsBlockRootsIterator::*;

        match self {
            PreFinalization {
                iter,
                continuation_data,
            } => {
                match iter.next() {
                    Some(x) => Some(x),
                    // Once the pre-finalization iterator is consumed, transition
                    // to a post-finalization iterator beginning from the last slot
                    // of the pre iterator.
                    None => {
                        let (end_state, end_block_root) =
                            continuation_data.take().or_else(|| {
                                error!(
                                    iter.inner.store.log,
                                    "HybridForwardsBlockRootsIterator: logic error"
                                );
                                None
                            })?;

                        *self = PostFinalization {
                            iter: SimpleForwardsBlockRootsIterator::new(
                                iter.inner.store.clone(),
                                Slot::from(iter.inner.end_vindex),
                                end_state,
                                end_block_root,
                            ),
                        };
                        self.next()
                    }
                }
            }
            PostFinalization { iter } => iter.next(),
        }
    }
}
