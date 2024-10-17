use crate::hdiff::{Error, HDiffBuffer};
use crate::metrics;
use lru::LruCache;
use std::num::NonZeroUsize;
use types::{BeaconState, ChainSpec, EthSpec, Slot};

/// Holds a combination of finalized states in two formats:
/// - `hdiff_buffers`: Format close to an SSZ serialized state for rapid application of diffs on top
///   of it
/// - `states`: Deserialized states for direct use or for rapid application of blocks (replay)
///
/// An example use: when requesting state data for consecutive slots, this cache allows the node to
/// apply diffs once on the first request, and latter just apply blocks one at a time.
#[derive(Debug)]
pub struct HistoricStateCache<E: EthSpec> {
    hdiff_buffers: LruCache<Slot, HDiffBuffer>,
    states: LruCache<Slot, BeaconState<E>>,
}

#[derive(Debug, Default)]
pub struct Metrics {
    pub num_hdiff: usize,
    pub num_state: usize,
    pub hdiff_byte_size: usize,
}

impl<E: EthSpec> HistoricStateCache<E> {
    pub fn new(hdiff_buffer_cache_size: NonZeroUsize, state_cache_size: NonZeroUsize) -> Self {
        Self {
            hdiff_buffers: LruCache::new(hdiff_buffer_cache_size),
            states: LruCache::new(state_cache_size),
        }
    }

    pub fn get_hdiff_buffer(&mut self, slot: Slot) -> Option<HDiffBuffer> {
        if let Some(buffer_ref) = self.hdiff_buffers.get(&slot) {
            let _timer = metrics::start_timer(&metrics::BEACON_HDIFF_BUFFER_CLONE_TIMES);
            Some(buffer_ref.clone())
        } else if let Some(state) = self.states.get(&slot) {
            let buffer = HDiffBuffer::from_state(state.clone());
            let _timer = metrics::start_timer(&metrics::BEACON_HDIFF_BUFFER_CLONE_TIMES);
            let cloned = buffer.clone();
            drop(_timer);
            self.hdiff_buffers.put(slot, cloned);
            Some(buffer)
        } else {
            None
        }
    }

    pub fn get_state(
        &mut self,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Result<Option<BeaconState<E>>, Error> {
        if let Some(state) = self.states.get(&slot) {
            Ok(Some(state.clone()))
        } else if let Some(buffer) = self.hdiff_buffers.get(&slot) {
            let state = buffer.as_state(spec)?;
            self.states.put(slot, state.clone());
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    pub fn put_state(&mut self, slot: Slot, state: BeaconState<E>) {
        self.states.put(slot, state);
    }

    pub fn put_hdiff_buffer(&mut self, slot: Slot, buffer: HDiffBuffer) {
        self.hdiff_buffers.put(slot, buffer);
    }

    pub fn put_both(&mut self, slot: Slot, state: BeaconState<E>, buffer: HDiffBuffer) {
        self.put_state(slot, state);
        self.put_hdiff_buffer(slot, buffer);
    }

    pub fn metrics(&self) -> Metrics {
        let hdiff_byte_size = self
            .hdiff_buffers
            .iter()
            .map(|(_, buffer)| buffer.size())
            .sum::<usize>();
        Metrics {
            num_hdiff: self.hdiff_buffers.len(),
            num_state: self.states.len(),
            hdiff_byte_size,
        }
    }
}
