//! Space-efficient storage for `BeaconState` vector fields.
//!
//! This module provides logic for splitting the `FixedVector` fields of a `BeaconState` into
//! chunks, and storing those chunks in contiguous ranges in the on-disk database.  The motiviation
//! for doing this is avoiding massive duplication in every on-disk state.  For example, rather than
//! storing the whole `active_index_roots` vector, which is updated once per epoch, at every slot,
//! we instead store all the historical values as a chunked vector on-disk, and fetch only the slice
//! we need when reconstructing the `active_index_roots` of a state.
//!
//! ## Terminology
//!
//! * **Chunk size**: the number of vector values stored per on-disk chunk.
//! * **Vector index** (vindex): index into all the historical values, identifying a single element
//!   of the vector being stored.
//! * **Chunk index** (cindex): index into the keyspace of the on-disk database, identifying a chunk
//!   of elements. To find the chunk index of a vector index: `cindex = vindex / chunk_size`.
// TODO(michael): do we need a term for modulo vector indices
// TODO: Historical index? (hindex)
use crate::*;
use ssz::{Decode, Encode};
use typenum::Unsigned;

use self::UpdatePattern::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePattern {
    // The entry at the state's previous slot is the most recently updated.
    OncePerSlotPrev,
    OncePerEpoch,
    // Temporary hack for active index roots (they have look-ahead!)
    Air,
    OncePerNSlotsPrev { n: u64 },
}

pub trait Field<E: EthSpec>: Copy {
    /// The `Default` impl will be used to fill extra vector entries.
    type Value: Decode + Encode + Default + Clone + PartialEq;
    type Length: Unsigned;

    fn update_pattern() -> UpdatePattern;

    fn column() -> DBColumn;

    // TODO(michael): tweak chunk size as appropriate
    fn chunk_size() -> usize {
        8
    }

    /// Get the value of this field at the given vector index from the state.
    fn get_value(
        state: &BeaconState<E>,
        vindex: u64,
        spec: &ChainSpec,
    ) -> Result<Self::Value, BeaconStateError>;

    /// Compute the start and end vector indices of the slice of history required at `current_slot`.
    ///
    /// ## Example
    ///
    /// If we have a field that is updated once per epoch, then the end vindex will be the current
    /// epoch, and the start vindex will be `end_vindex - length + 1`, where `length` is the length
    /// of the vector field (the `N` in `FixedVector<T, N>`).
    fn start_and_end_vindex(current_slot: Slot, spec: &ChainSpec) -> (usize, usize) {
        // Take advantage of saturating subtraction on slots and epochs
        match Self::update_pattern() {
            OncePerSlotPrev => {
                let start_slot = current_slot - Self::Length::to_u64();
                (start_slot.as_usize(), current_slot.as_usize())
            }
            OncePerEpoch => {
                let end_epoch = current_slot.epoch(E::slots_per_epoch()) + 1;
                let start_epoch = end_epoch - Self::Length::to_u64();
                (start_epoch.as_usize(), end_epoch.as_usize())
            }
            Air => {
                let current_epoch = current_slot.epoch(E::slots_per_epoch());
                let end_epoch = current_epoch + spec.activation_exit_delay + 1;
                let start_epoch = end_epoch - Self::Length::to_u64();
                (start_epoch.as_usize(), end_epoch.as_usize())
            }
            OncePerNSlotsPrev { n } => {
                let end_vindex = current_slot.as_u64() / n;
                let start_vindex = end_vindex.saturating_sub(Self::Length::to_u64());
                (start_vindex as usize, end_vindex as usize)
            }
        }
    }

    fn get_updated_chunk(
        existing_chunk: &Chunk<Self::Value>,
        chunk_index: usize,
        start_vindex: usize,
        end_vindex: usize,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Chunk<Self::Value>, Error> {
        // TODO: this could likely be more efficient
        let chunk_size = Self::chunk_size();
        let mut new_chunk = Chunk::new(vec![Self::Value::default(); chunk_size]);

        for i in 0..chunk_size {
            let vindex = chunk_index * chunk_size + i;
            if vindex >= start_vindex && vindex < end_vindex {
                let vector_value = Self::get_value(state, vindex as u64, spec)?;
                new_chunk.values[i] = vector_value;
            } else {
                new_chunk.values[i] = existing_chunk
                    .values
                    .get(i)
                    .cloned()
                    .unwrap_or_else(Self::Value::default);
            }
        }

        Ok(new_chunk)
    }
}

trait VariableLengthField<E: EthSpec>: Field<E> {}

macro_rules! field {
    ($struct_name:ident, $value_ty:ty, $length_ty:ty, $update_pattern:expr,
     $column:expr, $get_value:expr) => {
        #[derive(Clone, Copy)]
        pub struct $struct_name;

        impl<T> Field<T> for $struct_name
        where
            T: EthSpec,
        {
            type Value = $value_ty;
            type Length = $length_ty;

            fn update_pattern() -> UpdatePattern {
                $update_pattern
            }

            fn column() -> DBColumn {
                $column
            }

            fn get_value(
                state: &BeaconState<T>,
                vindex: u64,
                spec: &ChainSpec,
            ) -> Result<Self::Value, BeaconStateError> {
                $get_value(state, vindex, spec)
            }
        }
    };
}

field!(
    BlockRoots,
    Hash256,
    T::SlotsPerHistoricalRoot,
    OncePerSlotPrev,
    DBColumn::BeaconBlockRoots,
    |state: &BeaconState<_>, index, _| state.get_block_root(Slot::new(index)).map(|x| *x)
);

field!(
    StateRoots,
    Hash256,
    T::SlotsPerHistoricalRoot,
    OncePerSlotPrev,
    DBColumn::BeaconStateRoots,
    |state: &BeaconState<_>, index, _| state.get_state_root(Slot::new(index)).map(|x| *x)
);

field!(
    HistoricalRoots,
    Hash256,
    T::HistoricalRootsLimit,
    OncePerNSlotsPrev {
        n: T::SlotsPerHistoricalRoot::to_u64()
    },
    DBColumn::BeaconHistoricalRoots,
    |state: &BeaconState<_>, vindex, _| state
        .historical_roots
        .get(vindex as usize)
        .map(|x| *x)
        .ok_or(BeaconStateError::SlotOutOfBounds)
);

impl<E: EthSpec> VariableLengthField<E> for HistoricalRoots {}

field!(
    RandaoMixes,
    Hash256,
    T::EpochsPerHistoricalVector,
    OncePerEpoch,
    DBColumn::BeaconRandaoMixes,
    |state: &BeaconState<_>, index, _| state.get_randao_mix(Epoch::new(index)).map(|x| *x)
);

field!(
    ActiveIndexRoots,
    Hash256,
    T::EpochsPerHistoricalVector,
    Air,
    DBColumn::BeaconActiveIndexRoots,
    |state: &BeaconState<_>, index, spec| state.get_active_index_root(Epoch::new(index), spec)
);

field!(
    CompactCommitteesRoots,
    Hash256,
    T::EpochsPerHistoricalVector,
    OncePerEpoch,
    DBColumn::BeaconCompactCommitteesRoots,
    |state: &BeaconState<_>, index, _| state.get_compact_committee_root(Epoch::new(index))
);

pub fn store_updated_vector<F: Field<E>, E: EthSpec, S: Store>(
    field: F,
    store: &S,
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    println!("Storing vector for {:?}", F::column());
    let chunk_size = F::chunk_size();
    let (start_vindex, end_vindex) = F::start_and_end_vindex(state.slot, spec);
    let start_tindex = start_vindex / chunk_size;
    let end_tindex = end_vindex / chunk_size;

    println!("start_vindex: {}, end_vindex: {}", start_vindex, end_vindex);
    println!("start_tindex: {}, end_tindex: {}", start_tindex, end_tindex);

    // Start by iterating backwards from the last chunk, storing new chunks in the database.
    // Stop once a chunk in the database matches what we were about to store, this indicates
    // that a previously stored state has already filled-in a portion of the indices covered.
    let full_range_checked = store_range(
        field,
        (start_tindex..=end_tindex).rev(),
        start_vindex,
        end_vindex,
        store,
        state,
        spec,
    )?;

    // If the previous `store_range` did not check the entire range, it may be the case that the
    // state's vector includes elements at low vector indices that are not yet stored in the
    // database, so run another `store_range` to ensure these values are also stored.
    if !full_range_checked {
        store_range(
            field,
            start_tindex..end_tindex,
            start_vindex,
            end_vindex,
            store,
            state,
            spec,
        )?;
    }

    Ok(())
}

fn store_range<F, E, S, I>(
    _: F,
    range: I,
    start_vindex: usize,
    end_vindex: usize,
    store: &S,
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<bool, Error>
where
    F: Field<E>,
    E: EthSpec,
    S: Store,
    I: Iterator<Item = usize>,
{
    for chunk_index in range {
        println!("Checking the chunk at cindex {}", chunk_index);

        let chunk_key = &integer_key(chunk_index as u64)[..];

        let existing_chunk =
            Chunk::<F::Value>::load(store, F::column(), chunk_key)?.unwrap_or_else(Chunk::default);

        let new_chunk = F::get_updated_chunk(
            &existing_chunk,
            chunk_index,
            start_vindex,
            end_vindex,
            state,
            spec,
        )?;

        if new_chunk == existing_chunk {
            println!("Duplicate chunk found, exiting");
            return Ok(false);
        }

        new_chunk.store(store, F::column(), chunk_key)?;
    }

    Ok(true)
}

fn integer_key(index: u64) -> [u8; 8] {
    index.to_be_bytes()
}

// Chunks at the end index are included.
// TODO: could be more efficient with a real range query (perhaps RocksDB)
fn range_query<S: Store, T: Decode + Encode>(
    store: &S,
    column: DBColumn,
    start_index: usize,
    end_index: usize,
) -> Result<Vec<Chunk<T>>, Error> {
    let mut result = vec![];

    println!("{:?}: ranging over {}..={}", column, start_index, end_index);

    for table_index in start_index..=end_index {
        let key = &integer_key(table_index as u64)[..];
        let chunk =
            Chunk::load(store, column, key)?.ok_or(ChunkError::MissingChunk { table_index })?;
        result.push(chunk);
    }

    Ok(result)
}

fn stitch<F: Field<E>, E: EthSpec>(
    chunks: Vec<Chunk<F::Value>>,
    start_vindex: usize,
    end_vindex: usize,
    chunk_size: usize,
    length: usize,
) -> Result<Vec<F::Value>, ChunkError> {
    if end_vindex - start_vindex > length {
        // FIXME(michael): change this error
        return Err(ChunkError::SlotIntervalTooLarge);
    }

    let start_tindex = start_vindex / chunk_size;
    let end_tindex = end_vindex / chunk_size;

    let mut result = vec![F::Value::default(); length];

    for (chunk_index, chunk) in (start_tindex..=end_tindex).zip(chunks.into_iter()) {
        // All chunks but the last chunk must be full-sized
        if chunk_index != end_tindex && chunk.values.len() != chunk_size {
            return Err(ChunkError::InvalidChunkSize);
        }

        // Copy the chunk entries into the result vector
        for (i, value) in chunk.values.into_iter().enumerate() {
            let vindex = chunk_index * chunk_size + i;

            if vindex >= start_vindex && vindex < end_vindex {
                result[vindex % length] = value;
            }
        }
    }

    Ok(result)
}

pub fn load_vector_from_db<F: Field<E>, E: EthSpec, S: Store>(
    store: &S,
    slot: Slot,
    spec: &ChainSpec,
) -> Result<FixedVector<F::Value, F::Length>, Error> {
    // Do a range query
    let chunk_size = F::chunk_size();
    let (start_vindex, end_vindex) = F::start_and_end_vindex(slot, spec);
    let start_tindex = start_vindex / chunk_size;
    let end_tindex = end_vindex / chunk_size;

    let chunks = range_query(store, F::column(), start_tindex, end_tindex)?;

    let result = stitch::<F, E>(
        chunks,
        start_vindex,
        end_vindex,
        chunk_size,
        F::Length::to_usize(),
    )?;

    Ok(result.into())
}

/// The historical roots are stored in vector chunks, despite not actually being a vector.
pub fn load_variable_list_from_db<F: Field<E>, E: EthSpec, S: Store>(
    store: &S,
    slot: Slot,
    spec: &ChainSpec,
) -> Result<VariableList<F::Value, F::Length>, Error> {
    let chunk_size = F::chunk_size();
    let (start_vindex, end_vindex) = F::start_and_end_vindex(slot, spec);
    let start_tindex = start_vindex / chunk_size;
    let end_tindex = end_vindex / chunk_size;

    let chunks: Vec<Chunk<F::Value>> = range_query(store, F::column(), start_tindex, end_tindex)?;

    let mut result = Vec::with_capacity(chunk_size * chunks.len());

    for (chunk_index, chunk) in chunks.into_iter().enumerate() {
        for (i, value) in chunk.values.into_iter().enumerate() {
            let vindex = chunk_index * chunk_size + i;

            if vindex >= start_vindex && vindex < end_vindex {
                result.push(value);
            }
        }
    }

    Ok(result.into())
}

/// A chunk of a fixed-size vector from the `BeaconState`, stored in the database.
#[derive(Debug, Clone, PartialEq)]
pub struct Chunk<T: Decode + Encode> {
    /// A vector of up-to `chunk_size` values.
    pub values: Vec<T>,
}

impl<T> Default for Chunk<T>
where
    T: Decode + Encode,
{
    fn default() -> Self {
        Chunk { values: vec![] }
    }
}

impl<T> Chunk<T>
where
    T: Decode + Encode,
{
    pub fn new(values: Vec<T>) -> Self {
        Chunk { values }
    }

    pub fn load<S: Store>(store: &S, column: DBColumn, key: &[u8]) -> Result<Option<Self>, Error> {
        store
            .get_bytes(column.into(), key)?
            .map(|bytes| Self::decode(&bytes))
            .transpose()
    }

    pub fn store<S: Store>(&self, store: &S, column: DBColumn, key: &[u8]) -> Result<(), Error> {
        store.put_bytes(column.into(), key, &self.encode()?)?;
        Ok(())
    }

    /// Attempt to decode a single chunk, returning the chunk and the number of bytes read.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        // NOTE: could have a sub-trait for fixed length SSZ types?
        if !<T as Decode>::is_ssz_fixed_len() {
            return Err(Error::from(ChunkError::ChunkTypeInvalid));
        }

        // Read the appropriate number of values
        let mut offset = 0;
        let mut values = vec![];
        let value_size = <T as Decode>::ssz_fixed_len();

        while offset < bytes.len() {
            let value_bytes =
                bytes
                    .get(offset..offset + value_size)
                    .ok_or(ChunkError::OutOfBounds {
                        i: offset + value_size - 1,
                        len: bytes.len(),
                    })?;
            let value = T::from_ssz_bytes(value_bytes)?;
            values.push(value);
            offset += value_size;
        }

        Ok(Chunk { values })
    }

    pub fn encoded_size(&self) -> usize {
        self.values.len() * <T as Encode>::ssz_fixed_len()
    }

    /// Encode a single chunk as bytes.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        // NOTE: could have a sub-trait for fixed length SSZ types?
        if !<T as Decode>::is_ssz_fixed_len() {
            return Err(Error::from(ChunkError::ChunkTypeInvalid));
        }

        let mut result = Vec::with_capacity(self.encoded_size());

        // Values
        for value in &self.values {
            result.extend(value.as_ssz_bytes());
        }

        Ok(result)
    }
}

#[derive(Debug, PartialEq)]
pub enum ChunkError {
    OutOfBounds { i: usize, len: usize },
    OversizedChunk,
    InvalidChunkSize,
    MissingChunk { table_index: usize },
    ChunkTypeInvalid,
    SlotIntervalTooLarge,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn stitch_basic() {
        fn v(i: u64) -> Hash256 {
            Hash256::from_low_u64_be(i)
        }

        let chunk_size = 4;

        let chunks = vec![
            Chunk::new(vec![v(0), v(1), v(2), v(3)]),
            Chunk::new(vec![v(4), v(5), v(6), v(7)]),
            Chunk::new(vec![v(8), v(9), v(10), v(11)]),
        ];

        assert_eq!(
            stitch(chunks.clone(), 0, 11, chunk_size, 12).unwrap(),
            (0..12).map(v).collect::<Vec<_>>()
        );

        assert_eq!(
            stitch(chunks.clone(), 2, 9, chunk_size, 8).unwrap(),
            vec![v(8), v(9), v(2), v(3), v(4), v(5), v(6), v(7)]
        );
    }
}
