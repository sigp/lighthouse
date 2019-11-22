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

/// Map a chunk index to bytes that can be used to key the NoSQL database.
///
/// We shift chunks up by 1 to make room for a genesis chunk that is handled separately.
fn chunk_key(cindex: u64) -> [u8; 8] {
    (cindex + 1).to_be_bytes()
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

    /// Get the value of this field at the given vector index, from the state.
    fn get_value(
        state: &BeaconState<E>,
        vindex: u64,
        spec: &ChainSpec,
    ) -> Result<Self::Value, BeaconStateError>;

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

        let mut inconsistent = false;
        for i in 0..chunk_size {
            let vindex = chunk_index * chunk_size + i;
            if vindex >= start_vindex && vindex < end_vindex {
                let vector_value = Self::get_value(state, vindex as u64, spec)?;

                if let Some(existing_value) = existing_chunk.values.get(i) {
                    if *existing_value != vector_value && *existing_value != Self::Value::default()
                    {
                        if !inconsistent {
                            println!(
                                "INCONSISTENT: existing_chunk: {:#?}\nstate: {:#?}",
                                existing_chunk.values, state
                            );
                            inconsistent = true;
                        }
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
                Ok($get_value(state, vindex, spec))
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
    // FIXME(sproul): use safe accessors, or otherwise avoid div by 0
    |state: &BeaconState<_>, index, _| state.block_roots[index as usize % state.block_roots.len()]
);

field!(
    StateRoots,
    FixedLengthField,
    Hash256,
    T::SlotsPerHistoricalRoot,
    DBColumn::BeaconStateRoots,
    |_| OncePerNSlots { n: 1 },
    |state: &BeaconState<_>, index, _| state.state_roots[index as usize % state.state_roots.len()]
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
    |state: &BeaconState<_>, vindex, _| state.historical_roots
        [vindex as usize % state.historical_roots.len()]
);

field!(
    RandaoMixes,
    FixedLengthField,
    Hash256,
    T::EpochsPerHistoricalVector,
    DBColumn::BeaconRandaoMixes,
    |_| OncePerEpoch { offset: Lag(1) },
    |state: &BeaconState<_>, index, _| state.randao_mixes
        [index as usize % state.randao_mixes.len()]
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

    // Store the genesis value if we have access to it, and it hasn't been stored already.
    if slot_needs_genesis_value::<F, _>(state.slot, spec) {
        let genesis_value = extract_genesis_value::<F, _>(state, spec)?;
        println!(
            "{:?}: from slot {}, storing genesis value {:?}",
            F::column(),
            state.slot.as_u64(),
            genesis_value
        );
        check_and_store_genesis_value::<F, _, _>(store, genesis_value)?;
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
        let chunk_key = &chunk_key(chunk_index as u64)[..];

        let existing_chunk =
            Chunk::<F::Value>::load(store, F::column(), chunk_key)?.unwrap_or_else(Chunk::default);

        println!(
            "{:?}: get_updated_chunk at slot {}, cindex {}, {}..{}",
            F::column(),
            state.slot.as_u64(),
            chunk_index,
            start_vindex,
            end_vindex
        );
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
        let key = &chunk_key(chunk_index as u64)[..];
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

/// Load the genesis value for a fixed length field from the 0th chunk in the store.
///
/// This genesis value should be used to fill the initial state of the vector.
// FIXME(sproul): for middle-out sync we will have to ensure the genesis value is stored
// ahead-of-time.
pub fn load_genesis_value<F: FixedLengthField<E>, E: EthSpec, S: Store>(
    store: &S,
) -> Result<F::Value, Error> {
    let key = &genesis_value_key()[..];
    let chunk = Chunk::load(store, F::column(), key)?.ok_or(ChunkError::MissingGenesisValue)?;
    chunk
        .values
        .first()
        .cloned()
        .ok_or(ChunkError::MissingGenesisValue.into())
}

pub fn check_and_store_genesis_value<F: Field<E>, E: EthSpec, S: Store>(
    store: &S,
    value: F::Value,
) -> Result<(), Error> {
    let key = &genesis_value_key()[..];
    if let Some(existing_chunk) = Chunk::<F::Value>::load(store, F::column(), key)? {
        assert_eq!(existing_chunk.values.len(), 1);
        assert_eq!(existing_chunk.values[0], value);
        println!("Genesis value OK");
        Ok(())
    } else {
        store_genesis_value::<F, E, S>(store, value)
    }
}

pub fn store_genesis_value<F: Field<E>, E: EthSpec, S: Store>(
    store: &S,
    value: F::Value,
) -> Result<(), Error> {
    let chunk = Chunk::new(vec![value]);
    chunk.store(store, F::column(), &genesis_value_key()[..])
}

fn slot_needs_genesis_value<F: Field<E>, E: EthSpec>(slot: Slot, spec: &ChainSpec) -> bool {
    let (_, end_vindex) = F::start_and_end_vindex(slot, spec);
    match F::update_pattern(spec) {
        OncePerNSlots { .. } => {
            // If the end_vindex is less than the length of the vector, then the vector
            // has not yet been completely filled with non-genesis values, and so the genesis
            // value is still required.
            F::is_fixed_length() && end_vindex < F::Length::to_usize()
        }
        // FIXME(sproul): randao hacks, generalise
        OncePerEpoch { .. } => F::is_fixed_length() && end_vindex + 1 < F::Length::to_usize(),
    }
}

fn extract_genesis_value<F: Field<E>, E: EthSpec>(
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<F::Value, Error> {
    let (_, end_vindex) = F::start_and_end_vindex(state.slot, spec);
    match F::update_pattern(spec) {
        OncePerNSlots { .. } => {
            // Genesis value is guaranteed to exist at `end_vindex`, as it won't yet have been updated
            // (assuming `slot_needs_genesis_value` returned true).
            Ok(F::get_value(state, end_vindex as u64, spec)?)
        }
        // FIXME(sproul): randao hacks, generalise
        OncePerEpoch { .. } => Ok(F::get_value(state, end_vindex as u64 + 1, spec)?),
    }
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

    let default = if slot_needs_genesis_value::<F, _>(slot, spec) {
        load_genesis_value::<F, _, _>(store)?
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
        println!("storing chunk for {:?} at key {}", column, key[7]);
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
    MissingGenesisValue,
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
    use types::test_utils::TestingBeaconStateBuilder;
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
            stitch(chunks.clone(), 2, 6, chunk_size, 12, 99).unwrap(),
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
            stitch(chunks.clone(), 2, 10, chunk_size, 8, default).unwrap(),
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

    fn test_state(validator_count: usize) -> (BeaconState<TestSpec>, Vec<KeyPair>, ChainSpec) {
        let spec = TestSpec::default_spec();
        let builder =
            TestingBeaconStateBuilder::from_deterministic_keypairs(validator_count, &spec);
        let (state, keypairs) = builder.build();
        (state, keypairs, spec)
    }

    /*
    #[test]
    fn roundtrip_beacon_state() {
        let num_validators = 8;
        let (mut state, keypairs, spec) = test_state(num_validators);


    }
    */
}
