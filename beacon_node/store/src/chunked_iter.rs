use crate::chunked_vector::{chunk_key, Chunk, Field};
use crate::{HotColdDB, ItemStore};
use slog::error;
use types::{ChainSpec, EthSpec, Slot};
use crate::StoreError as Error;
use crate::{DBColumn, KeyValueStore};
use ssz::{Decode, Encode};
use types::{Hash256};

/// Iterator over the values of a `BeaconState` vector field (like `block_roots`).
///
/// Uses the freezer DB's separate table to load the values.
pub struct ChunkedVectorIter<'a, F, E, Hot, Cold>
where
    F: Field<E>,
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    pub(crate) store: &'a HotColdDB<E, Hot, Cold>,
    current_vindex: usize,
    pub(crate) end_vindex: usize,
    next_cindex: usize,
    current_chunk: Chunk<F::Value>,
}

impl<'a, F, E, Hot, Cold> ChunkedVectorIter<'a, F, E, Hot, Cold>
where
    F: Field<E>,
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    /// Create a new iterator which can yield elements from `start_vindex` up to the last
    /// index stored by the restore point at `last_restore_point_slot`.
    ///
    /// The `freezer_upper_limit` slot should be the slot of a recent restore point as obtained from
    /// `Root::freezer_upper_limit`. We pass it as a parameter so that the caller can
    /// maintain a stable view of the database (see `HybridForwardsBlockRootsIterator`).
    pub fn new(
        store: &'a HotColdDB<E, Hot, Cold>,
        start_vindex: usize,
        freezer_upper_limit: Slot,
        spec: &ChainSpec,
    ) -> Self {
        let (_, end_vindex) = F::start_and_end_vindex(freezer_upper_limit, spec);

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

impl<F, E, Hot, Cold> Iterator for ChunkedVectorIter<'_, F, E, Hot, Cold>
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

pub struct ChunkedIter<'a, E, Store: KeyValueStore<E>> {
    store: &'a Store,
    column: DBColumn,
    current_chunk: Option<Vec<Hash256>>,
    current_index: usize,
    chunk_size: usize,
    total_size: usize,
    _phantom: std::marker::PhantomData<E>,
}

impl<'a, E, Store: KeyValueStore<E>> ChunkedIter<'a, E, Store> {
    pub fn new(
        store: &'a Store,
        column: DBColumn,
        chunk_size: usize,
        total_size: usize,
    ) -> Result<Self, Error> {
        let mut iter = Self {
            store,
            column,
            current_chunk: None,
            current_index: 0,
            chunk_size,
            total_size,
            _phantom: std::marker::PhantomData,
        };
        
        iter.load_next_chunk()?;
        Ok(iter)
    }
    
    fn load_next_chunk(&mut self) -> Result<(), Error> {
        let chunk_index = self.current_index / self.chunk_size;
        if chunk_index * self.chunk_size >= self.total_size {
            self.current_chunk = None;
            return Ok(());
        }
        
        let key = chunk_index.to_le_bytes();
        let chunk_bytes = self.store.get_bytes(self.column, &key)?
            .ok_or_else(|| Error::DBError("Missing chunk".into()))?;
            
        self.current_chunk = Some(Vec::<Hash256>::from_ssz_bytes(&chunk_bytes)?);
        Ok(())
    }
}

impl<'a, E, Store: KeyValueStore<E>> Iterator for ChunkedIter<'a, E, Store> {
    type Item = Result<Hash256, Error>;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index >= self.total_size {
            return None;
        }
        
        let chunk = match &self.current_chunk {
            Some(chunk) => chunk,
            None => return Some(Err(Error::DBError("No current chunk".into()))),
        };
        
        let item_index = self.current_index % self.chunk_size;
        let result = chunk.get(item_index)
            .cloned()
            .ok_or_else(|| Error::DBError("Invalid chunk index".into()));
            
        self.current_index += 1;
        
        if item_index + 1 == chunk.len() {
            if let Err(e) = self.load_next_chunk() {
                return Some(Err(e));
            }
        }
        
        Some(result)
    }
    
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total_size.saturating_sub(self.current_index);
        (remaining, Some(remaining))
    }
}
