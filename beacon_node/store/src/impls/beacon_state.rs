use crate::*;
use ssz::Encode;
use ssz_derive::Encode;
use std::io::{Read, Write};
use std::sync::Arc;
use types::{CompactBeaconState, PublicKeyBytes};
use zstd::{Decoder, Encoder};

pub fn store_full_state<E: EthSpec>(
    state_root: &Hash256,
    state: &BeaconState<E>,
    ops: &mut Vec<KeyValueStoreOp>,
    config: &StoreConfig,
) -> Result<(), Error> {
    let bytes = {
        let _overhead_timer = metrics::start_timer(&metrics::BEACON_STATE_WRITE_OVERHEAD_TIMES);
        StorageContainer::new(state).as_ssz_bytes()
    };
    let mut compressed_value = Vec::with_capacity(config.estimate_compressed_size(bytes.len()));
    let mut encoder = Encoder::new(&mut compressed_value, config.compression_level)
        .map_err(Error::Compression)?;
    encoder.write_all(&bytes).map_err(Error::Compression)?;
    encoder.finish().map_err(Error::Compression)?;

    metrics::inc_counter_by(
        &metrics::BEACON_STATE_WRITE_BYTES,
        compressed_value.len() as u64,
    );
    metrics::inc_counter(&metrics::BEACON_STATE_WRITE_COUNT);

    let key = get_key_for_col(DBColumn::BeaconState.into(), state_root.as_bytes());
    ops.push(KeyValueStoreOp::PutKeyValue(key, compressed_value));
    Ok(())
}

pub fn get_full_state<KV: KeyValueStore<E>, E: EthSpec, F>(
    db: &KV,
    state_root: &Hash256,
    immutable_validators: F,
    config: &StoreConfig,
    spec: &ChainSpec,
) -> Result<Option<BeaconState<E>>, Error>
where
    F: Fn(usize) -> Option<Arc<PublicKeyBytes>>,
{
    let total_timer = metrics::start_timer(&metrics::BEACON_STATE_READ_TIMES);

    match db.get_bytes(DBColumn::BeaconState.into(), state_root.as_bytes())? {
        Some(bytes) => {
            let mut ssz_bytes = Vec::with_capacity(config.estimate_decompressed_size(bytes.len()));
            let mut decoder = Decoder::new(&*bytes).map_err(Error::Compression)?;
            decoder
                .read_to_end(&mut ssz_bytes)
                .map_err(Error::Compression)?;

            let overhead_timer = metrics::start_timer(&metrics::BEACON_STATE_READ_OVERHEAD_TIMES);
            let container = StorageContainer::from_ssz_bytes(&ssz_bytes, spec)?;

            metrics::stop_timer(overhead_timer);
            metrics::stop_timer(total_timer);
            metrics::inc_counter(&metrics::BEACON_STATE_READ_COUNT);
            metrics::inc_counter_by(&metrics::BEACON_STATE_READ_BYTES, bytes.len() as u64);

            Ok(Some(container.into_beacon_state(immutable_validators)?))
        }
        None => Ok(None),
    }
}

/// A container for storing `BeaconState` components.
#[derive(Encode)]
pub struct StorageContainer<T: EthSpec> {
    state: CompactBeaconState<T>,
}

impl<T: EthSpec> StorageContainer<T> {
    /// Create a new instance for storing a `BeaconState`.
    pub fn new(state: &BeaconState<T>) -> Self {
        Self {
            state: state.clone().into_compact_state(),
        }
    }

    pub fn from_ssz_bytes(bytes: &[u8], spec: &ChainSpec) -> Result<Self, ssz::DecodeError> {
        // We need to use the slot-switching `from_ssz_bytes` of `BeaconState`, which doesn't
        // compose with the other SSZ utils, so we duplicate some parts of `ssz_derive` here.
        let mut builder = ssz::SszDecoderBuilder::new(bytes);

        builder.register_anonymous_variable_length_item()?;

        let mut decoder = builder.build()?;

        let state =
            decoder.decode_next_with(|bytes| CompactBeaconState::from_ssz_bytes(bytes, spec))?;

        Ok(Self { state })
    }

    fn into_beacon_state<F>(self, immutable_validators: F) -> Result<BeaconState<T>, Error>
    where
        F: Fn(usize) -> Option<Arc<PublicKeyBytes>>,
    {
        let state = self.state.try_into_full_state(immutable_validators)?;
        Ok(state)
    }
}
