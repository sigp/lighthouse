use crate::*;
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::convert::TryInto;
use types::beacon_state::{BeaconTreeHashCache, CommitteeCache, CACHED_EPOCHS};

pub fn store_full_state<S: Store, E: EthSpec>(
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

pub fn get_full_state<S: Store, E: EthSpec>(
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
struct StorageContainer {
    state_bytes: Vec<u8>,
    committee_caches_bytes: Vec<Vec<u8>>,
    tree_hash_cache_bytes: Vec<u8>,
}

impl StorageContainer {
    /// Create a new instance for storing a `BeaconState`.
    pub fn new<T: EthSpec>(state: &BeaconState<T>) -> Self {
        let mut committee_caches_bytes = vec![];

        for cache in state.committee_caches[..].iter() {
            committee_caches_bytes.push(cache.as_ssz_bytes());
        }

        let tree_hash_cache_bytes = state.tree_hash_cache.as_ssz_bytes();

        Self {
            state_bytes: state.as_ssz_bytes(),
            committee_caches_bytes,
            tree_hash_cache_bytes,
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

        state.tree_hash_cache = BeaconTreeHashCache::from_ssz_bytes(&self.tree_hash_cache_bytes)?;

        Ok(state)
    }
}
