use crate::*;
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::convert::TryInto;
use types::beacon_state::{CommitteeCache, CACHED_EPOCHS};

/// A container for storing `BeaconState` components.
#[derive(Encode, Decode)]
struct StorageContainer {
    state_bytes: Vec<u8>,
    committee_caches_bytes: Vec<Vec<u8>>,
}

impl StorageContainer {
    /// Create a new instance for storing a `BeaconState`.
    pub fn new<T: EthSpec>(state: &BeaconState<T>) -> Self {
        let mut committee_caches_bytes = vec![];

        for cache in state.committee_caches[..].iter() {
            committee_caches_bytes.push(cache.as_ssz_bytes());
        }

        Self {
            state_bytes: state.as_ssz_bytes(),
            committee_caches_bytes,
        }
    }
}

impl<T: EthSpec> TryInto<BeaconState<T>> for StorageContainer {
    type Error = Error;

    fn try_into(self) -> Result<BeaconState<T>, Error> {
        let mut state: BeaconState<T> = BeaconState::from_ssz_bytes(&self.state_bytes)?;

        for i in 0..CACHED_EPOCHS {
            let bytes = &self.committee_caches_bytes.get(i).ok_or_else(|| {
                Error::SszDecodeError(DecodeError::BytesInvalid(
                    "Insufficient committees for BeaconState".to_string(),
                ))
            })?;

            state.committee_caches[i] = CommitteeCache::from_ssz_bytes(bytes)?;
        }

        Ok(state)
    }
}

impl<T: EthSpec> StoreItem for BeaconState<T> {
    fn db_column() -> DBColumn {
        DBColumn::BeaconState
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        let timer = metrics::start_timer(&metrics::BEACON_STATE_WRITE_TIMES);

        let container = StorageContainer::new(self);
        let bytes = container.as_ssz_bytes();

        metrics::stop_timer(timer);
        metrics::inc_counter(&metrics::BEACON_STATE_WRITE_COUNT);
        metrics::inc_counter_by(&metrics::BEACON_STATE_WRITE_BYTES, bytes.len() as i64);

        bytes
    }

    fn from_store_bytes(bytes: &mut [u8]) -> Result<Self, Error> {
        let timer = metrics::start_timer(&metrics::BEACON_STATE_READ_TIMES);

        let len = bytes.len();
        let container = StorageContainer::from_ssz_bytes(bytes)?;
        let result = container.try_into();

        metrics::stop_timer(timer);
        metrics::inc_counter(&metrics::BEACON_STATE_READ_COUNT);
        metrics::inc_counter_by(&metrics::BEACON_STATE_READ_BYTES, len as i64);

        result
    }
}
