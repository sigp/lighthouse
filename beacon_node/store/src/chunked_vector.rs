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
use crate::*;
use ssz::{Decode, Encode};
use typenum::Unsigned;

use self::{EpochOffset::*, UpdatePattern::*};

/// Description of how a `BeaconState` field is updated during state processing.
///
/// When storing a state, this allows us to efficiently store only those entries
/// which are not present in the DB already.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePattern {
    /// The value is updated once per `n` slots.
    OncePerNSlots { n: u64 },
    /// The value is updated once per epoch, for the epoch `current_epoch +- offset`.
    OncePerEpoch { offset: EpochOffset },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochOffset {
    Lookahead(u64),
    Lag(u64),
}

impl EpochOffset {
    fn lookahead_and_lag(self) -> (u64, u64) {
        match self {
            Lookahead(n) => (n, 0),
            Lag(n) => (0, n),
        }
    }
}

/// Trait for types representing fields of the `BeaconState`.
///
/// All of the required methods are type-level, because we do most things with fields at the
/// type-level. We require their value-level witnesses to be `Copy` so that we can avoid the
/// turbofish when calling functions like `store_updated_vector`.
pub trait Field<E: EthSpec>: Copy {
    /// The type of value stored in this field: the `T` from `FixedVector<T, N>`.
    ///
    /// The `Default` impl will be used to fill extra vector entries.
    type Value: Decode + Encode + Default + Clone + PartialEq + std::fmt::Debug;

    /// The length of this field: the `N` from `FixedVector<T, N>`.
    type Length: Unsigned;

    /// The database column where the integer-indexed chunks for this field should be stored.
    ///
    /// Each field's column **must** be unique.
    fn column() -> DBColumn;

    /// Update pattern for this field, so that we can do differential updates.
    fn update_pattern(spec: &ChainSpec) -> UpdatePattern;

    /// The number of values to store per chunk on disk.
    ///
    /// Default is 128 so that we read/write 4K pages when the values are 32 bytes.
    // TODO: benchmark and optimise this parameter
    fn chunk_size() -> usize {
        128
    }

    /// Get the value of this field at the given vector index, from the state.
    fn get_value(
        state: &BeaconState<E>,
        vindex: u64,
        spec: &ChainSpec,
    ) -> Result<Self::Value, BeaconStateError>;

    /// Compute the start and end vector indices of the slice of history required at `current_slot`.
    ///
    /// ## Example
    ///
    /// If we have a field that is updated once per epoch, then the end vindex will be
    /// `current_epoch + 1`, because we want to include the value for the current epoch, and the
    /// start vindex will be `end_vindex - Self::Length`, because that's how far back we can look.
    fn start_and_end_vindex(current_slot: Slot, spec: &ChainSpec) -> (usize, usize) {
        // We take advantage of saturating subtraction on slots and epochs
        match Self::update_pattern(spec) {
            OncePerNSlots { n } => {
                // Per-slot changes exclude the index for the current slot, because
                // it won't be set until the slot completes (think of `state_roots`, `block_roots`).
                // This also works for the `historical_roots` because at the `n`th slot, the 0th
                // entry of the list is created, and before that the list is empty.
                let end_vindex = current_slot / n;
                let start_vindex = end_vindex - Self::Length::to_u64();
                (start_vindex.as_usize(), end_vindex.as_usize())
            }
            OncePerEpoch { offset } => {
                // Per-epoch changes include the index for the current epoch, because it
                // will have been set at the most recent epoch boundary.
                let (lookahead, lag) = offset.lookahead_and_lag();
                let current_epoch = current_slot.epoch(E::slots_per_epoch());
                let end_epoch = current_epoch + 1 + lookahead - lag;
                let start_epoch = end_epoch + lag - Self::Length::to_u64();
                (start_epoch.as_usize(), end_epoch.as_usize())
            }
        }
    }

    /// Given an `existing_chunk` stored in the DB, construct an updated chunk to replace it.
    fn get_updated_chunk(
        existing_chunk: &Chunk<Self::Value>,
        chunk_index: usize,
        start_vindex: usize,
        end_vindex: usize,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Chunk<Self::Value>, Error> {
        let chunk_size = Self::chunk_size();
        let mut new_chunk = Chunk::new(vec![Self::Value::default(); chunk_size]);

        for i in 0..chunk_size {
            let vindex = chunk_index * chunk_size + i;
            if vindex >= start_vindex && vindex < end_vindex {
                let vector_value = Self::get_value(state, vindex as u64, spec)?;

                if let Some(existing_value) = existing_chunk.values.get(i) {
                    if *existing_value != vector_value && *existing_value != Self::Value::default()
                    {
                        return Err(ChunkError::Inconsistent {
                            field: Self::column(),
                            chunk_index,
                        }
                        .into());
                    }
                }

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

/// Marker trait for fixed-length fields (`FixedVector<T, N>`).
pub trait FixedLengthField<E: EthSpec>: Field<E> {}

/// Marker trait for variable-length fields (`VariableList<T, N>`).
pub trait VariableLengthField<E: EthSpec>: Field<E> {}

/// Macro to implement the `Field` trait on a new unit struct type.
macro_rules! field {
    ($struct_name:ident, $marker_trait:ident, $value_ty:ty, $length_ty:ty, $column:expr,
     $update_pattern:expr, $get_value:expr) => {
        #[derive(Clone, Copy)]
        pub struct $struct_name;

        impl<T> Field<T> for $struct_name
        where
            T: EthSpec,
        {
            type Value = $value_ty;
            type Length = $length_ty;

            fn column() -> DBColumn {
                $column
            }

            fn update_pattern(spec: &ChainSpec) -> UpdatePattern {
                $update_pattern(spec)
            }

            fn get_value(
                state: &BeaconState<T>,
                vindex: u64,
                spec: &ChainSpec,
            ) -> Result<Self::Value, BeaconStateError> {
                $get_value(state, vindex, spec)
            }
        }

        impl<E: EthSpec> $marker_trait<E> for $struct_name {}
    };
}

field!(
    BlockRoots,
    FixedLengthField,
    Hash256,
    T::SlotsPerHistoricalRoot,
    DBColumn::BeaconBlockRoots,
    |_| OncePerNSlots { n: 1 },
    |state: &BeaconState<_>, index, _| state.get_block_root(Slot::new(index)).map(|x| *x)
);

field!(
    StateRoots,
    FixedLengthField,
    Hash256,
    T::SlotsPerHistoricalRoot,
    DBColumn::BeaconStateRoots,
    |_| OncePerNSlots { n: 1 },
    |state: &BeaconState<_>, index, _| state.get_state_root(Slot::new(index)).map(|x| *x)
);

field!(
    HistoricalRoots,
    VariableLengthField,
    Hash256,
    T::HistoricalRootsLimit,
    DBColumn::BeaconHistoricalRoots,
    |_| OncePerNSlots {
        n: T::SlotsPerHistoricalRoot::to_u64()
    },
    |state: &BeaconState<_>, vindex, _| state
        .historical_roots
        .get(vindex as usize)
        .map(|x| *x)
        .ok_or(BeaconStateError::SlotOutOfBounds)
);

field!(
    RandaoMixes,
    FixedLengthField,
    Hash256,
    T::EpochsPerHistoricalVector,
    DBColumn::BeaconRandaoMixes,
    |_| OncePerEpoch { offset: Lag(1) },
    |state: &BeaconState<_>, index, _| state.get_randao_mix(Epoch::new(index)).map(|x| *x)
);

field!(
    ActiveIndexRoots,
    FixedLengthField,
    Hash256,
    T::EpochsPerHistoricalVector,
    DBColumn::BeaconActiveIndexRoots,
    |spec: &ChainSpec| OncePerEpoch {
        offset: Lookahead(spec.activation_exit_delay)
    },
    |state: &BeaconState<_>, index, spec| state.get_active_index_root(Epoch::new(index), spec)
);

field!(
    CompactCommitteesRoots,
    FixedLengthField,
    Hash256,
    T::EpochsPerHistoricalVector,
    DBColumn::BeaconCompactCommitteesRoots,
    |_| OncePerEpoch {
        offset: Lookahead(0)
    },
    |state: &BeaconState<_>, index, _| state.get_compact_committee_root(Epoch::new(index))
);

pub fn store_updated_vector<F: Field<E>, E: EthSpec, S: Store>(
    field: F,
    store: &S,
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let chunk_size = F::chunk_size();
    let (start_vindex, end_vindex) = F::start_and_end_vindex(state.slot, spec);
    let start_cindex = start_vindex / chunk_size;
    let end_cindex = end_vindex / chunk_size;

    // Start by iterating backwards from the last chunk, storing new chunks in the database.
    // Stop once a chunk in the database matches what we were about to store, this indicates
    // that a previously stored state has already filled-in a portion of the indices covered.
    let full_range_checked = store_range(
        field,
        (start_cindex..=end_cindex).rev(),
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
            start_cindex..end_cindex,
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

    for chunk_index in start_index..=end_index {
        let key = &integer_key(chunk_index as u64)[..];
        let chunk = Chunk::load(store, column, key)?.ok_or(ChunkError::Missing { chunk_index })?;
        result.push(chunk);
    }

    Ok(result)
}

fn stitch<T: Default + Clone>(
    chunks: Vec<Chunk<T>>,
    start_vindex: usize,
    end_vindex: usize,
    chunk_size: usize,
    length: usize,
) -> Result<Vec<T>, ChunkError> {
    if start_vindex + length < end_vindex {
        return Err(ChunkError::OversizedRange {
            start_vindex,
            end_vindex,
            length,
        });
    }

    let start_cindex = start_vindex / chunk_size;
    let end_cindex = end_vindex / chunk_size;

    let mut result = vec![T::default(); length];

    for (chunk_index, chunk) in (start_cindex..=end_cindex).zip(chunks.into_iter()) {
        // All chunks but the last chunk must be full-sized
        if chunk_index != end_cindex && chunk.values.len() != chunk_size {
            return Err(ChunkError::InvalidSize {
                chunk_index,
                expected: chunk_size,
                actual: chunk.values.len(),
            });
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

pub fn load_vector_from_db<F: FixedLengthField<E>, E: EthSpec, S: Store>(
    store: &S,
    slot: Slot,
    spec: &ChainSpec,
) -> Result<FixedVector<F::Value, F::Length>, Error> {
    // Do a range query
    let chunk_size = F::chunk_size();
    let (start_vindex, end_vindex) = F::start_and_end_vindex(slot, spec);
    let start_cindex = start_vindex / chunk_size;
    let end_cindex = end_vindex / chunk_size;

    let chunks = range_query(store, F::column(), start_cindex, end_cindex)?;

    let result = stitch(
        chunks,
        start_vindex,
        end_vindex,
        chunk_size,
        F::Length::to_usize(),
    )?;

    Ok(result.into())
}

/// The historical roots are stored in vector chunks, despite not actually being a vector.
pub fn load_variable_list_from_db<F: VariableLengthField<E>, E: EthSpec, S: Store>(
    store: &S,
    slot: Slot,
    spec: &ChainSpec,
) -> Result<VariableList<F::Value, F::Length>, Error> {
    let chunk_size = F::chunk_size();
    let (start_vindex, end_vindex) = F::start_and_end_vindex(slot, spec);
    let start_cindex = start_vindex / chunk_size;
    let end_cindex = end_vindex / chunk_size;

    let chunks: Vec<Chunk<F::Value>> = range_query(store, F::column(), start_cindex, end_cindex)?;

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
pub struct Chunk<T> {
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

    /// Attempt to decode a single chunk.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if !<T as Decode>::is_ssz_fixed_len() {
            return Err(Error::from(ChunkError::InvalidType));
        }

        let value_size = <T as Decode>::ssz_fixed_len();

        if value_size == 0 {
            return Err(Error::from(ChunkError::InvalidType));
        }

        let values = bytes
            .chunks(value_size)
            .map(T::from_ssz_bytes)
            .collect::<Result<_, _>>()?;

        Ok(Chunk { values })
    }

    pub fn encoded_size(&self) -> usize {
        self.values.len() * <T as Encode>::ssz_fixed_len()
    }

    /// Encode a single chunk as bytes.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if !<T as Encode>::is_ssz_fixed_len() {
            return Err(Error::from(ChunkError::InvalidType));
        }

        Ok(self.values.iter().flat_map(T::as_ssz_bytes).collect())
    }
}

#[derive(Debug, PartialEq)]
pub enum ChunkError {
    InvalidSize {
        chunk_index: usize,
        expected: usize,
        actual: usize,
    },
    Missing {
        chunk_index: usize,
    },
    Inconsistent {
        field: DBColumn,
        chunk_index: usize,
    },
    InvalidType,
    OversizedRange {
        start_vindex: usize,
        end_vindex: usize,
        length: usize,
    },
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
            stitch(chunks.clone(), 0, 12, chunk_size, 12).unwrap(),
            (0..12).map(v).collect::<Vec<_>>()
        );

        assert_eq!(
            stitch(chunks.clone(), 2, 10, chunk_size, 8).unwrap(),
            vec![v(8), v(9), v(2), v(3), v(4), v(5), v(6), v(7)]
        );
    }
}
