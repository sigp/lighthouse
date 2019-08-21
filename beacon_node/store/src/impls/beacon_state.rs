use crate::*;
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::convert::TryInto;
use types::beacon_state::{CommitteeCache, CACHED_EPOCHS};

pub fn store_full_state<S: Store, E: EthSpec>(
    store: &S,
    state_root: &Hash256,
    state: &BeaconState<E>,
) -> Result<(), Error> {
    store.put_bytes(
        DBColumn::BeaconState.into(),
        state_root.as_bytes(),
        &StorageContainer::new(state).as_ssz_bytes(),
    )
}

pub fn get_full_state<S: Store, E: EthSpec>(
    store: &S,
    state_root: &Hash256,
) -> Result<Option<BeaconState<E>>, Error> {
    match store.get_bytes(DBColumn::BeaconState.into(), state_root.as_bytes())? {
        Some(bytes) => {
            let container = StorageContainer::from_ssz_bytes(&bytes)?;
            Ok(Some(container.try_into()?))
        }
        None => Ok(None),
    }
}

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
