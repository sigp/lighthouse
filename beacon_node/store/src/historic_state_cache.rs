use crate::hdiff::{Error, HDiffBuffer};
use lru::LruCache;
use std::num::NonZeroUsize;
use types::{BeaconState, ChainSpec, EthSpec, Slot};

/// Empty HDiffBuffer used to replace a real buffer temporarily during mutation.
const EMPTY_HDIFF_BUFFER: HDiffBuffer = HDiffBuffer {
    state: Vec::new(),
    balances: Vec::new(),
};

#[derive(Debug)]
pub enum HistoricState<E: EthSpec> {
    State(BeaconState<E>),
    HDiff(HDiffBuffer),
    Both(BeaconState<E>, HDiffBuffer),
}

#[derive(Debug)]
pub struct HistoricStateCache<E: EthSpec> {
    cache: LruCache<Slot, HistoricState<E>>,
}

impl<E: EthSpec> HistoricState<E> {
    fn as_hdiff_buffer(&mut self) -> HDiffBuffer {
        match self {
            HistoricState::State(state) => {
                let buffer = HDiffBuffer::from_state(state.clone());
                *self = HistoricState::Both(state.clone(), buffer.clone());
                buffer
            }
            HistoricState::HDiff(buffer) | HistoricState::Both(_, buffer) => buffer.clone(),
        }
    }

    fn as_state(&mut self, spec: &ChainSpec) -> Result<BeaconState<E>, Error> {
        match self {
            HistoricState::HDiff(buffer) => {
                let state = buffer.as_state(spec)?;
                let buffer = std::mem::replace(buffer, EMPTY_HDIFF_BUFFER);
                *self = HistoricState::Both(state.clone(), buffer);
                Ok(state)
            }
            HistoricState::State(state) | HistoricState::Both(state, _) => Ok(state.clone()),
        }
    }
}

impl<E: EthSpec> HistoricStateCache<E> {
    pub fn new(cache_size: NonZeroUsize) -> Self {
        Self {
            cache: LruCache::new(cache_size),
        }
    }

    pub fn get_hdiff_buffer(&mut self, slot: Slot) -> Option<HDiffBuffer> {
        self.cache
            .get_mut(&slot)
            .map(HistoricState::as_hdiff_buffer)
    }

    pub fn get_state(
        &mut self,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Result<Option<BeaconState<E>>, Error> {
        self.cache
            .get_mut(&slot)
            .map(|entry| entry.as_state(spec))
            .transpose()
    }

    pub fn put_state(&mut self, slot: Slot, state: BeaconState<E>) {
        let cache_entry = self
            .cache
            .get_or_insert_mut(slot, || HistoricState::State(state.clone()));
        if let HistoricState::HDiff(buffer) = cache_entry {
            let buffer = std::mem::replace(buffer, EMPTY_HDIFF_BUFFER);
            *cache_entry = HistoricState::Both(state, buffer);
        }
    }

    pub fn put_hdiff_buffer(&mut self, slot: Slot, buffer: HDiffBuffer) {
        let cache_entry = self
            .cache
            .get_or_insert_mut(slot, || HistoricState::HDiff(buffer.clone()));
        if let HistoricState::State(state) = cache_entry {
            *cache_entry = HistoricState::Both(state.clone(), buffer);
        }
    }

    pub fn put_both(&mut self, slot: Slot, state: BeaconState<E>, buffer: HDiffBuffer) {
        self.cache.put(slot, HistoricState::Both(state, buffer));
    }
}
