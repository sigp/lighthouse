use crate::*;
use serde_derive::{Deserialize, Serialize};
use std::default::Default;

/// Cache structure to avoid having to call compute_proposer_index each time.
/// This should get updated at the start of every new epoch.
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
        self.epoch
            .ok_or(Error::ProposerIndicesEpochCacheUninitialized)
            .and_then(|epoch| {
                if Slot::new(slot).epoch(T::slots_per_epoch()) == epoch {
                    self.indices
                        .as_ref()
                        .ok_or(Error::ProposerIndicesCacheIncomplete)
                        .and_then(|indices| {
                            let slot_index = slot % T::slots_per_epoch() as u64;
                            indices
                                .get(slot_index as usize)
                                .ok_or(Error::ProposerIndicesCacheIncomplete)
                                .map(|i| *i)
                        })
                } else {
                    Err(Error::ProposerIndicesCacheMismatch)
                }
            })
    }
}
