use crate::chunked_vector::{chunk_key, Chunk, Field};
use crate::DiskStore;
use std::sync::Arc;
use types::{ChainSpec, EthSpec, Slot};

pub struct ChunkedVectorIter<F, E>
where
    F: Field<E>,
    E: EthSpec,
{
    pub(crate) store: Arc<DiskStore<E>>,
    current_vindex: usize,
    pub(crate) end_vindex: usize,
    next_cindex: usize,
    current_chunk: Chunk<F::Value>,
}

impl<F, E> ChunkedVectorIter<F, E>
where
    F: Field<E>,
    E: EthSpec,
{
    // FIXME(sproul): check end_vindex > start_vindex
    pub fn new(
        store: Arc<DiskStore<E>>,
        start_vindex: usize,
        last_restore_point_slot: Slot,
        spec: &ChainSpec,
    ) -> Self {
        let (_, end_vindex) = F::start_and_end_vindex(last_restore_point_slot, spec);

        // Set the next chunk to be loaded to the one containing `start_vindex`.
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

impl<F, E> Iterator for ChunkedVectorIter<F, E>
where
    F: Field<E>,
    E: EthSpec,
{
    type Item = (usize, F::Value);

    // FIXME(sproul): log error if out of range, or chunk load fails
    fn next(&mut self) -> Option<Self::Item> {
        let chunk_size = F::chunk_size();

        // Range exhausted, return `None` forever.
        if self.current_vindex >= self.end_vindex {
            None
        }
        // Value lies in the current chunk, return it.
        else if self.current_vindex < self.next_cindex * chunk_size {
            let i = self.current_vindex % chunk_size;
            let vindex = self.current_vindex;
            let val = self.current_chunk.values.get(i).cloned()?;
            self.current_vindex += 1;
            Some((vindex, val))
        }
        // Need to load the next chunk, load it and recurse back into the in-range case.
        else {
            self.current_chunk = Chunk::load::<_, E>(
                &self.store.cold_db,
                F::column(),
                &chunk_key(self.next_cindex as u64),
            )
            .ok()??;
            self.next_cindex += 1;
            self.next()
        }
    }
}
