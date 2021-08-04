//! Space-efficient storage for `BeaconState` vector fields.
//!
//! This module provides logic for splitting the `FixedVector` fields of a `BeaconState` into
//! chunks, and storing those chunks in contiguous ranges in the on-disk database.  The motiviation
//! for doing this is avoiding massive duplication in every on-disk state.  For example, rather than
//! storing the whole `historical_roots` vector, which is updated once every couple of thousand
//! slots, at every slot, we instead store all the historical values as a chunked vector on-disk,
//! and fetch only the slice we need when reconstructing the `historical_roots` of a state.
//!
//! ## Terminology
//!
//! * **Chunk size**: the number of vector values stored per on-disk chunk.
//! * **Vector index** (vindex): index into all the historical values, identifying a single element
//!   of the vector being stored.
//! * **Chunk index** (cindex): index into the keyspace of the on-disk database, identifying a chunk
//!   of elements. To find the chunk index of a vector index: `cindex = vindex / chunk_size`.
use self::UpdatePattern::*;
use crate::*;
use ssz::{Decode, Encode};
use typenum::Unsigned;

/// Description of how a `BeaconState` field is updated during state processing.
///
/// When storing a state, this allows us to efficiently store only those entries
/// which are not present in the DB already.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePattern {
    /// The value is updated once per `n` slots.
    OncePerNSlots { n: u64 },
    /// The value is updated once per epoch, for the epoch `current_epoch - lag`.
    OncePerEpoch { lag: u64 },
}

/// Map a chunk index to bytes that can be used to key the NoSQL database.
///
/// We shift chunks up by 1 to make room for a genesis chunk that is handled separately.
pub fn chunk_key(cindex: usize) -> [u8; 8] {
    (cindex as u64 + 1).to_be_bytes()
}

/// Return the database key for the genesis value.
fn genesis_value_key() -> [u8; 8] {
    0u64.to_be_bytes()
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

    /// Convert a v-index (vector index) to a chunk index.
    fn chunk_index(vindex: usize) -> usize {
        vindex / Self::chunk_size()
    }

    /// Get the value of this field at the given vector index, from the state.
    fn get_value(
        state: &BeaconState<E>,
        vindex: u64,
        spec: &ChainSpec,
    ) -> Result<Self::Value, ChunkError>;

    /// True if this is a `FixedLengthField`, false otherwise.
    fn is_fixed_length() -> bool;

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
            OncePerEpoch { lag } => {
                // Per-epoch changes include the index for the current epoch, because it
                // will have been set at the most recent epoch boundary.
                let current_epoch = current_slot.epoch(E::slots_per_epoch());
                let end_epoch = current_epoch + 1 - lag;
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
                            existing_value: format!("{:?}", existing_value),
                            new_value: format!("{:?}", vector_value),
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

    /// Determine whether a state at `slot` possesses (or requires) the genesis value.
    fn slot_needs_genesis_value(slot: Slot, spec: &ChainSpec) -> bool {
        let (_, end_vindex) = Self::start_and_end_vindex(slot, spec);
        match Self::update_pattern(spec) {
            // If the end_vindex is less than the length of the vector, then the vector
            // has not yet been completely filled with non-genesis values, and so the genesis
            // value is still required.
            OncePerNSlots { .. } => {
                Self::is_fixed_length() && end_vindex < Self::Length::to_usize()
            }
            // If the field has lag, then it takes an extra `lag` vindices beyond the
            // `end_vindex` before the vector has been filled with non-genesis values.
            OncePerEpoch { lag } => {
                Self::is_fixed_length() && end_vindex + (lag as usize) < Self::Length::to_usize()
            }
        }
    }

    /// Load the genesis value for a fixed length field from the store.
    ///
    /// This genesis value should be used to fill the initial state of the vector.
    fn load_genesis_value<S: KeyValueStore<E>>(store: &S) -> Result<Self::Value, Error> {
        let key = &genesis_value_key()[..];
        let chunk =
            Chunk::load(store, Self::column(), key)?.ok_or(ChunkError::MissingGenesisValue)?;
        chunk
            .values
            .first()
            .cloned()
            .ok_or_else(|| ChunkError::MissingGenesisValue.into())
    }

    /// Store the given `value` as the genesis value for this field, unless stored already.
    ///
    /// Check the existing value (if any) for consistency with the value we intend to store, and
    /// return an error if they are inconsistent.
    fn check_and_store_genesis_value<S: KeyValueStore<E>>(
        store: &S,
        value: Self::Value,
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        let key = &genesis_value_key()[..];

        if let Some(existing_chunk) = Chunk::<Self::Value>::load(store, Self::column(), key)? {
            if existing_chunk.values.len() != 1 {
                Err(ChunkError::InvalidGenesisChunk {
                    field: Self::column(),
                    expected_len: 1,
                    observed_len: existing_chunk.values.len(),
                }
                .into())
            } else if existing_chunk.values[0] != value {
                Err(ChunkError::InconsistentGenesisValue {
                    field: Self::column(),
                    existing_value: format!("{:?}", existing_chunk.values[0]),
                    new_value: format!("{:?}", value),
                }
                .into())
            } else {
                Ok(())
            }
        } else {
            let chunk = Chunk::new(vec![value]);
            chunk.store(Self::column(), &genesis_value_key()[..], ops)?;
            Ok(())
        }
    }

    /// Extract the genesis value for a fixed length field from an
    ///
    /// Will only return a correct value if `slot_needs_genesis_value(state.slot(), spec) == true`.
    fn extract_genesis_value(
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Self::Value, Error> {
        let (_, end_vindex) = Self::start_and_end_vindex(state.slot(), spec);
        match Self::update_pattern(spec) {
            // Genesis value is guaranteed to exist at `end_vindex`, as it won't yet have been
            // updated
            OncePerNSlots { .. } => Ok(Self::get_value(state, end_vindex as u64, spec)?),
            // If there's lag, the value of the field at the vindex *without the lag*
            // should still be set to the genesis value.
            OncePerEpoch { lag } => Ok(Self::get_value(state, end_vindex as u64 + lag, spec)?),
        }
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
            ) -> Result<Self::Value, ChunkError> {
                $get_value(state, vindex, spec)
            }

            fn is_fixed_length() -> bool {
                stringify!($marker_trait) == "FixedLengthField"
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
    |state: &BeaconState<_>, index, _| safe_modulo_index(state.block_roots(), index)
);

field!(
    StateRoots,
    FixedLengthField,
    Hash256,
    T::SlotsPerHistoricalRoot,
    DBColumn::BeaconStateRoots,
    |_| OncePerNSlots { n: 1 },
    |state: &BeaconState<_>, index, _| safe_modulo_index(state.state_roots(), index)
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
    |state: &BeaconState<_>, index, _| safe_modulo_index(state.historical_roots(), index)
);

field!(
    RandaoMixes,
    FixedLengthField,
    Hash256,
    T::EpochsPerHistoricalVector,
    DBColumn::BeaconRandaoMixes,
    |_| OncePerEpoch { lag: 1 },
    |state: &BeaconState<_>, index, _| safe_modulo_index(state.randao_mixes(), index)
);

pub fn store_updated_vector<F: Field<E>, E: EthSpec, S: KeyValueStore<E>>(
    field: F,
    store: &S,
    state: &BeaconState<E>,
    spec: &ChainSpec,
    ops: &mut Vec<KeyValueStoreOp>,
) -> Result<(), Error> {
    let chunk_size = F::chunk_size();
    let (start_vindex, end_vindex) = F::start_and_end_vindex(state.slot(), spec);
    let start_cindex = start_vindex / chunk_size;
    let end_cindex = end_vindex / chunk_size;

    // Store the genesis value if we have access to it, and it hasn't been stored already.
    if F::slot_needs_genesis_value(state.slot(), spec) {
        let genesis_value = F::extract_genesis_value(state, spec)?;
        F::check_and_store_genesis_value(store, genesis_value, ops)?;
    }

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
        ops,
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
            ops,
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn store_range<F, E, S, I>(
    _: F,
    range: I,
    start_vindex: usize,
    end_vindex: usize,
    store: &S,
    state: &BeaconState<E>,
    spec: &ChainSpec,
    ops: &mut Vec<KeyValueStoreOp>,
) -> Result<bool, Error>
where
    F: Field<E>,
    E: EthSpec,
    S: KeyValueStore<E>,
    I: Iterator<Item = usize>,
{
    for chunk_index in range {
        let chunk_key = &chunk_key(chunk_index)[..];

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

        new_chunk.store(F::column(), chunk_key, ops)?;
    }

    Ok(true)
}

// Chunks at the end index are included.
// TODO: could be more efficient with a real range query (perhaps RocksDB)
fn range_query<S: KeyValueStore<E>, E: EthSpec, T: Decode + Encode>(
    store: &S,
    column: DBColumn,
    start_index: usize,
    end_index: usize,
) -> Result<Vec<Chunk<T>>, Error> {
    let range = start_index..=end_index;
    let len = range
        .end()
        // Add one to account for inclusive range.
        .saturating_add(1)
        .saturating_sub(*range.start());
    let mut result = Vec::with_capacity(len);

    for chunk_index in range {
        let key = &chunk_key(chunk_index)[..];
        let chunk = Chunk::load(store, column, key)?.ok_or(ChunkError::Missing { chunk_index })?;
        result.push(chunk);
    }

    Ok(result)
}

/// Combine chunks to form a list or vector of all values with vindex in `start_vindex..end_vindex`.
///
/// The `length` parameter is the length of the vec to construct, with entries set to `default` if
/// they lie outside the vindex range.
fn stitch<T: Default + Clone>(
    chunks: Vec<Chunk<T>>,
    start_vindex: usize,
    end_vindex: usize,
    chunk_size: usize,
    length: usize,
    default: T,
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

    let mut result = vec![default; length];

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

pub fn load_vector_from_db<F: FixedLengthField<E>, E: EthSpec, S: KeyValueStore<E>>(
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

    let default = if F::slot_needs_genesis_value(slot, spec) {
        F::load_genesis_value(store)?
    } else {
        F::Value::default()
    };

    let result = stitch(
        chunks,
        start_vindex,
        end_vindex,
        chunk_size,
        F::Length::to_usize(),
        default,
    )?;

    Ok(result.into())
}

/// The historical roots are stored in vector chunks, despite not actually being a vector.
pub fn load_variable_list_from_db<F: VariableLengthField<E>, E: EthSpec, S: KeyValueStore<E>>(
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

/// Index into a field of the state, avoiding out of bounds and division by 0.
fn safe_modulo_index<T: Copy>(values: &[T], index: u64) -> Result<T, ChunkError> {
    if values.is_empty() {
        Err(ChunkError::ZeroLengthVector)
    } else {
        Ok(values[index as usize % values.len()])
    }
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

    pub fn load<S: KeyValueStore<E>, E: EthSpec>(
        store: &S,
        column: DBColumn,
        key: &[u8],
    ) -> Result<Option<Self>, Error> {
        store
            .get_bytes(column.into(), key)?
            .map(|bytes| Self::decode(&bytes))
            .transpose()
    }

    pub fn store(
        &self,
        column: DBColumn,
        key: &[u8],
        ops: &mut Vec<KeyValueStoreOp>,
    ) -> Result<(), Error> {
        let db_key = get_key_for_col(column.into(), key);
        ops.push(KeyValueStoreOp::PutKeyValue(db_key, self.encode()?));
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
    ZeroLengthVector,
    InvalidSize {
        chunk_index: usize,
        expected: usize,
        actual: usize,
    },
    Missing {
        chunk_index: usize,
    },
    MissingGenesisValue,
    Inconsistent {
        field: DBColumn,
        chunk_index: usize,
        existing_value: String,
        new_value: String,
    },
    InconsistentGenesisValue {
        field: DBColumn,
        existing_value: String,
        new_value: String,
    },
    InvalidGenesisChunk {
        field: DBColumn,
        expected_len: usize,
        observed_len: usize,
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
    use types::MainnetEthSpec as TestSpec;
    use types::*;

    fn v(i: u64) -> Hash256 {
        Hash256::from_low_u64_be(i)
    }

    #[test]
    fn stitch_default() {
        let chunk_size = 4;

        let chunks = vec![
            Chunk::new(vec![0u64, 1, 2, 3]),
            Chunk::new(vec![4, 5, 0, 0]),
        ];

        assert_eq!(
            stitch(chunks, 2, 6, chunk_size, 12, 99).unwrap(),
            vec![99, 99, 2, 3, 4, 5, 99, 99, 99, 99, 99, 99]
        );
    }

    #[test]
    fn stitch_basic() {
        let chunk_size = 4;
        let default = v(0);

        let chunks = vec![
            Chunk::new(vec![v(0), v(1), v(2), v(3)]),
            Chunk::new(vec![v(4), v(5), v(6), v(7)]),
            Chunk::new(vec![v(8), v(9), v(10), v(11)]),
        ];

        assert_eq!(
            stitch(chunks.clone(), 0, 12, chunk_size, 12, default).unwrap(),
            (0..12).map(v).collect::<Vec<_>>()
        );

        assert_eq!(
            stitch(chunks, 2, 10, chunk_size, 8, default).unwrap(),
            vec![v(8), v(9), v(2), v(3), v(4), v(5), v(6), v(7)]
        );
    }

    #[test]
    fn stitch_oversized_range() {
        let chunk_size = 4;
        let default = 0;

        let chunks = vec![Chunk::new(vec![20u64, 21, 22, 23])];

        // Args (start_vindex, end_vindex, length)
        let args = vec![(0, 21, 20), (0, 2048, 1024), (0, 2, 1)];

        for (start_vindex, end_vindex, length) in args {
            assert_eq!(
                stitch(
                    chunks.clone(),
                    start_vindex,
                    end_vindex,
                    chunk_size,
                    length,
                    default
                ),
                Err(ChunkError::OversizedRange {
                    start_vindex,
                    end_vindex,
                    length,
                })
            );
        }
    }

    #[test]
    fn fixed_length_fields() {
        fn test_fixed_length<F: Field<TestSpec>>(_: F, expected: bool) {
            assert_eq!(F::is_fixed_length(), expected);
        }
        test_fixed_length(BlockRoots, true);
        test_fixed_length(StateRoots, true);
        test_fixed_length(HistoricalRoots, false);
        test_fixed_length(RandaoMixes, true);
    }

    fn needs_genesis_value_once_per_slot<F: Field<TestSpec>>(_: F) {
        let spec = &TestSpec::default_spec();
        let max = F::Length::to_u64();
        for i in 0..max {
            assert!(
                F::slot_needs_genesis_value(Slot::new(i), spec),
                "slot {}",
                i
            );
        }
        assert!(!F::slot_needs_genesis_value(Slot::new(max), spec));
    }

    #[test]
    fn needs_genesis_value_block_roots() {
        needs_genesis_value_once_per_slot(BlockRoots);
    }

    #[test]
    fn needs_genesis_value_state_roots() {
        needs_genesis_value_once_per_slot(StateRoots);
    }

    #[test]
    fn needs_genesis_value_historical_roots() {
        let spec = &TestSpec::default_spec();
        assert!(
            !<HistoricalRoots as Field<TestSpec>>::slot_needs_genesis_value(Slot::new(0), spec)
        );
    }

    fn needs_genesis_value_test_randao<F: Field<TestSpec>>(_: F) {
        let spec = &TestSpec::default_spec();
        let max = TestSpec::slots_per_epoch() as u64 * (F::Length::to_u64() - 1);
        for i in 0..max {
            assert!(
                F::slot_needs_genesis_value(Slot::new(i), spec),
                "slot {}",
                i
            );
        }
        assert!(!F::slot_needs_genesis_value(Slot::new(max), spec));
    }

    #[test]
    fn needs_genesis_value_randao() {
        needs_genesis_value_test_randao(RandaoMixes);
    }
}
