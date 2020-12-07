use crate::*;
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::convert::TryInto;
use types::beacon_state::{CloneConfig, CommitteeCache, CACHED_EPOCHS};

pub fn store_full_state<E: EthSpec>(
    state_root: &Hash256,
    state: &BeaconState<E>,
    ops: &mut Vec<KeyValueStoreOp>,
) -> Result<(), Error> {
    let bytes = {
        let _overhead_timer = metrics::start_timer(&metrics::BEACON_STATE_WRITE_OVERHEAD_TIMES);
        StorageContainer::new(state).as_ssz_bytes()
    };
    metrics::inc_counter_by(&metrics::BEACON_STATE_WRITE_BYTES, bytes.len() as u64);
    metrics::inc_counter(&metrics::BEACON_STATE_WRITE_COUNT);
    let key = get_key_for_col(DBColumn::BeaconState.into(), state_root.as_bytes());
    ops.push(KeyValueStoreOp::PutKeyValue(key, bytes));
    Ok(())
}

pub fn get_full_state<KV: KeyValueStore<E>, E: EthSpec>(
    db: &KV,
    state_root: &Hash256,
) -> Result<Option<BeaconState<E>>, Error> {
    let total_timer = metrics::start_timer(&metrics::BEACON_STATE_READ_TIMES);

    match db.get_bytes(DBColumn::BeaconState.into(), state_root.as_bytes())? {
        Some(bytes) => {
            let overhead_timer = metrics::start_timer(&metrics::BEACON_STATE_READ_OVERHEAD_TIMES);
            let container = StorageContainer::from_ssz_bytes(&bytes)?;

            metrics::stop_timer(overhead_timer);
            metrics::stop_timer(total_timer);
            metrics::inc_counter(&metrics::BEACON_STATE_READ_COUNT);
            metrics::inc_counter_by(&metrics::BEACON_STATE_READ_BYTES, bytes.len() as u64);

            Ok(Some(container.try_into()?))
        }
        None => Ok(None),
    }
}

/// A container for storing `BeaconState` components.
// TODO: would be more space efficient with the caches stored separately and referenced by hash
#[derive(Encode, Decode)]
pub struct StorageContainer<T: EthSpec> {
    state: BeaconState<T>,
    committee_caches: Vec<CommitteeCache>,
}

impl<T: EthSpec> StorageContainer<T> {
    /// Create a new instance for storing a `BeaconState`.
    pub fn new(state: &BeaconState<T>) -> Self {
        Self {
            state: state.clone_with(CloneConfig::none()),
            committee_caches: state.committee_caches.to_vec(),
        }
    }
}

impl<T: EthSpec> TryInto<BeaconState<T>> for StorageContainer<T> {
    type Error = Error;

    fn try_into(mut self) -> Result<BeaconState<T>, Error> {
        let mut state = self.state;

        for i in (0..CACHED_EPOCHS).rev() {
            if i >= self.committee_caches.len() {
                return Err(Error::SszDecodeError(DecodeError::BytesInvalid(
                    "Insufficient committees for BeaconState".to_string(),
                )));
            };

            state.committee_caches[i] = self.committee_caches.remove(i);
        }

        Ok(state)
    }
}
