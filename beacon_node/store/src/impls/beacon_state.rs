use crate::*;
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::convert::TryInto;
use types::beacon_state::{CommitteeCache, CACHED_EPOCHS};

pub fn store_full_state<S: Store<E>, E: EthSpec>(
    store: &S,
    state_root: &Hash256,
    state: &BeaconState<E>,
) -> Result<(), Error> {
    let timer = metrics::start_timer(&metrics::BEACON_STATE_WRITE_TIMES);

    let bytes = StorageContainer::new(state).as_ssz_bytes();
    let result = store.put_bytes(DBColumn::BeaconState.into(), state_root.as_bytes(), &bytes);

    metrics::stop_timer(timer);
    metrics::inc_counter(&metrics::BEACON_STATE_WRITE_COUNT);
    metrics::inc_counter_by(&metrics::BEACON_STATE_WRITE_BYTES, bytes.len() as i64);

    result
}

pub fn get_full_state<S: Store<E>, E: EthSpec>(
    store: &S,
    state_root: &Hash256,
) -> Result<Option<BeaconState<E>>, Error> {
    let timer = metrics::start_timer(&metrics::BEACON_STATE_READ_TIMES);

    match store.get_bytes(DBColumn::BeaconState.into(), state_root.as_bytes())? {
        Some(bytes) => {
            let container = StorageContainer::from_ssz_bytes(&bytes)?;

            metrics::stop_timer(timer);
            metrics::inc_counter(&metrics::BEACON_STATE_READ_COUNT);
            metrics::inc_counter_by(&metrics::BEACON_STATE_READ_BYTES, bytes.len() as i64);

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
            state: state.clone_without_caches(),
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
