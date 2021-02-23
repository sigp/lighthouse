use crate::chunked_vector::{chunk_key, Chunk, Field};
use crate::{Error, KeyValueStore, KeyValueStoreOp};
use types::EthSpec;

/// Buffered writer for chunked vectors (block roots mainly).
pub struct ChunkWriter<'a, F, E, S>
where
    F: Field<E>,
    E: EthSpec,
    S: KeyValueStore<E>,
{
    /// Buffered chunk awaiting writing to disk (always dirty).
    chunk: Chunk<F::Value>,
    /// Chunk index of `chunk`.
    index: usize,
    store: &'a S,
}

impl<'a, F, E, S> ChunkWriter<'a, F, E, S>
where
    F: Field<E>,
    E: EthSpec,
    S: KeyValueStore<E>,
{
    pub fn new(store: &'a S, vindex: usize) -> Result<Self, Error> {
        let chunk_index = F::chunk_index(vindex);
        let chunk = Chunk::load(store, F::column(), &chunk_key(chunk_index))?
            .unwrap_or_else(|| Chunk::new(vec![F::Value::default(); F::chunk_size()]));

        Ok(Self {
            chunk,
            index: chunk_index,
            store,
        })
    }

    /// Set the value at a given vector index, writing the current chunk and moving on if necessary.
    // TODO(sproul): inconsistency checks
    pub fn set(
        &mut self,
        vindex: usize,
        value: F::Value,
        batch: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        let chunk_index = F::chunk_index(vindex);

        // Advance to the next chunk.
        if chunk_index != self.index {
            self.write(batch)?;
            *self = Self::new(self.store, vindex)?;
        }

        self.chunk.values[vindex % F::chunk_size()] = value;
        Ok(())
    }

    /// Write the current chunk to disk.
    ///
    /// Should be called before the writer is dropped, in order to write the final chunk to disk.
    pub fn write(&self, batch: &mut Vec<KeyValueStoreOp>) -> Result<(), Error> {
        self.chunk.store(F::column(), &chunk_key(self.index), batch)
    }
}
