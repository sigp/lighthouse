use ssz::DecodeError;
use ssz_derive::Encode;
use std::convert::TryInto;
use std::sync::Arc;
use store::*;
use types::beacon_state::{CommitteeCache, CACHED_EPOCHS};

pub fn get_full_state<KV: KeyValueStore<E>, E: EthSpec>(
    db: &KV,
    state_root: &Hash256,
    spec: &ChainSpec,
) -> Result<Option<BeaconState<E>>, Error> {
    match db.get_bytes(DBColumn::BeaconState.into(), state_root.as_bytes())? {
        Some(bytes) => {
            let container = StorageContainer::from_ssz_bytes(&bytes, spec)?;
            Ok(Some(container.try_into()?))
        }
        None => Ok(None),
    }
}

/// A container for storing `BeaconState` components.
#[derive(Encode)]
pub struct StorageContainer<T: EthSpec> {
    state: BeaconState<T>,
    committee_caches: Vec<Arc<CommitteeCache>>,
}

impl<T: EthSpec> StorageContainer<T> {
    pub fn from_ssz_bytes(bytes: &[u8], spec: &ChainSpec) -> Result<Self, ssz::DecodeError> {
        // We need to use the slot-switching `from_ssz_bytes` of `BeaconState`, which doesn't
        // compose with the other SSZ utils, so we duplicate some parts of `ssz_derive` here.
        let mut builder = ssz::SszDecoderBuilder::new(bytes);

        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<Vec<CommitteeCache>>()?;

        let mut decoder = builder.build()?;

        let state = decoder.decode_next_with(|bytes| BeaconState::from_ssz_bytes(bytes, spec))?;
        let committee_caches = decoder.decode_next()?;

        Ok(Self {
            state,
            committee_caches,
        })
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

            state.committee_caches_mut()[i] = self.committee_caches.remove(i);
        }

        Ok(state)
    }
}
