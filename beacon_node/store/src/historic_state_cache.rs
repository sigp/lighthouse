use crate::StoreError as Error;
use crate::metrics;
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use types::{BeaconState, ChainSpec, EthSpec, Hash256, Slot};

/// Holds a combination of finalized states in two formats:
/// - `hdiff_buffers`: Format close to an SSZ serialized state for rapid application of diffs on top
///   of it
/// - `states`: Deserialized states for direct use or for rapid application of blocks (replay)
///
/// An example use: when requesting state data for consecutive slots, this cache allows the node to
/// apply diffs once on the first request, and latter just apply blocks one at a time.
#[derive(Debug)]
pub struct HistoricStateCache<E: EthSpec> {
    states: LruCache<Hash256, BeaconState<E>>,
    hdiff_buffers: HashMap<Slot, HDiffBuffer>,
}

#[derive(Debug, Default)]
pub struct Metrics {
    pub num_hdiff: usize,
    pub num_state: usize,
    pub hdiff_byte_size: usize,
}

impl<E: EthSpec> HistoricStateCache<E> {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            states: LruCache::new(capacity),
            hdiff_buffers: HashMap::new(),
        }
    }

    pub fn get(&mut self, state_root: &Hash256) -> Option<BeaconState<E>> {
        self.states.get(state_root).cloned()
    }

    pub fn put(&mut self, state_root: Hash256, state: BeaconState<E>) {
        self.states.put(state_root, state);
    }

    pub fn get_hdiff_buffer(&self, slot: Slot) -> Option<&HDiffBuffer> {
        self.hdiff_buffers.get(&slot)
    }

    pub fn put_hdiff_buffer(&mut self, slot: Slot, buffer: HDiffBuffer) {
        self.hdiff_buffers.insert(slot, buffer);
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

#[derive(Debug, Clone)]
pub struct HDiffBuffer {
    pub buffer: Vec<u8>,
    pub base_slot: Slot,
}

impl HDiffBuffer {
    pub fn new(buffer: Vec<u8>, base_slot: Slot) -> Self {
        Self { buffer, base_slot }
    }

    pub fn as_state(&self, spec: &ChainSpec) -> Result<BeaconState<E>, Error> {
        // Implementation of as_state method
        unimplemented!()
    }

    pub fn size(&self) -> usize {
        self.buffer.len()
    }
}
