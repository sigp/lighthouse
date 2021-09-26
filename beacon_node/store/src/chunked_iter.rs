use crate::chunked_vector::{chunk_key, Chunk, Field};
use crate::{HotColdDB, ItemStore};
use slog::error;
use std::sync::Arc;
use types::{ChainSpec, EthSpec, Slot};

/// Iterator over the values of a `BeaconState` vector field (like `block_roots`).
///
/// Uses the freezer DB's separate table to load the values.
pub struct ChunkedVectorIter<F, E, Hot, Cold>
where
    F: Field<E>,
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    pub(crate) store: Arc<HotColdDB<E, Hot, Cold>>,
    current_vindex: usize,
    pub(crate) end_vindex: usize,
    next_cindex: usize,
    current_chunk: Chunk<F::Value>,
}

impl<F, E, Hot, Cold> ChunkedVectorIter<F, E, Hot, Cold>
where
    F: Field<E>,
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    /// Create a new iterator which can yield elements from `start_vindex` up to the last
    /// index stored by the restore point at `last_restore_point_slot`.
    ///
    /// The `last_restore_point` slot should be the slot of a recent restore point as obtained from
    /// `HotColdDB::get_latest_restore_point_slot`. We pass it as a parameter so that the caller can
    /// maintain a stable view of the database (see `HybridForwardsBlockRootsIterator`).
    pub fn new(
        store: Arc<HotColdDB<E, Hot, Cold>>,
        start_vindex: usize,
        last_restore_point_slot: Slot,
        spec: &ChainSpec,
    ) -> Self {
        let (_, end_vindex) = F::start_and_end_vindex(last_restore_point_slot, spec);

        // Set the next chunk to the one containing `start_vindex`.
        let next_cindex = start_vindex / F::chunk_size();
        // Set the current chunk to the empty chunk, it will never be read.
        let current_chunk = Chunk::default();

        Self {
            store,
            current_vindex: start_vindex,
            end_vindex,
            next_cindex,
            current_chunk,
        }
    }
}

impl<F, E, Hot, Cold> Iterator for ChunkedVectorIter<F, E, Hot, Cold>
where
    F: Field<E>,
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    type Item = (usize, F::Value);

    fn next(&mut self) -> Option<Self::Item> {
        let chunk_size = F::chunk_size();

        // Range exhausted, return `None` forever.
        if self.current_vindex >= self.end_vindex {
            None
        }
        // Value lies in the current chunk, return it.
        else if self.current_vindex < self.next_cindex * chunk_size {
            let vindex = self.current_vindex;
            let val = self
                .current_chunk
                .values
                .get(vindex % chunk_size)
                .cloned()
                .or_else(|| {
                    error!(
                        self.store.log,
                        "Missing chunk value in forwards iterator";
                        "vector index" => vindex
                    );
                    None
                })?;
            self.current_vindex += 1;
            Some((vindex, val))
        }
        // Need to load the next chunk, load it and recurse back into the in-range case.
        else {
            self.current_chunk = Chunk::load(
                &self.store.cold_db,
                F::column(),
                &chunk_key(self.next_cindex),
            )
            .map_err(|e| {
                error!(
                    self.store.log,
                    "Database error in forwards iterator";
                    "chunk index" => self.next_cindex,
                    "error" => format!("{:?}", e)
                );
                e
            })
            .ok()?
            .or_else(|| {
                error!(
                    self.store.log,
                    "Missing chunk in forwards iterator";
                    "chunk index" => self.next_cindex
                );
                None
            })?;
            self.next_cindex += 1;
            self.next()
        }
    }
}
