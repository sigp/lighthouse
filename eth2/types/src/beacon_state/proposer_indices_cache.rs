use crate::*;
use serde_derive::{Deserialize, Serialize};
use std::default::Default;

/// SCOTT
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposerIndicesCache<T: EthSpec> {
    pub epoch: Option<Epoch>,
    indices: Option<FixedVector<usize, T::SlotsPerEpoch>>,
}

impl<T: EthSpec> Default for ProposerIndicesCache<T> {
    fn default() -> Self {
        Self {
            epoch: None,
            indices: None,
        }
    }
}

impl<T: EthSpec> ProposerIndicesCache<T> {
    pub fn new(epoch: Epoch, indices: FixedVector<usize, T::SlotsPerEpoch>) -> Self {
        Self {
            epoch: Some(epoch),
            indices: Some(indices),
        }
    }

    pub fn get_proposer_index_for_slot(&self, slot: u64) -> Result<usize, Error> {
        if let Some(indices) = &self.indices {
            let slot_index = slot % indices.len() as u64;
            indices
                .get(slot_index as usize)
                .ok_or(Error::ProposerIndicesCacheIncomplete)
                .map(|i| *i)
        } else {
            Err(Error::ProposerIndicesCacheUninitialized)
        }
    }
}
