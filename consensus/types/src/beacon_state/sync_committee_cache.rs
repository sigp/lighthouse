use crate::{BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec};

/// Cache the sync committee indices, as an accelerator for `get_sync_committee_indices`.
#[derive(Debug, Default, PartialEq, Clone)]
pub struct SyncCommitteeCache {
    cache: Option<Cache>,
}

#[derive(Debug, PartialEq, Clone)]
struct Cache {
    base_epoch: Epoch,
    sync_committee_indices: Vec<usize>,
}

impl SyncCommitteeCache {
    pub fn new<T: EthSpec>(
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<Self, BeaconStateError> {
        let base_epoch = state.sync_committee_base_epoch(state.current_epoch(), spec)?;
        let sync_committee_indices =
            state.compute_sync_committee_indices(state.current_epoch(), spec)?;
        Ok(SyncCommitteeCache {
            cache: Some(Cache {
                base_epoch,
                sync_committee_indices,
            }),
        })
    }

    pub fn is_initialized_for(&self, base_epoch: Epoch) -> bool {
        self.get_cache(base_epoch).is_some()
    }

    fn get_cache(&self, base_epoch: Epoch) -> Option<&Cache> {
        self.cache
            .as_ref()
            .filter(|cache| cache.base_epoch == base_epoch)
    }

    pub fn get_sync_committee_indices(&self, base_epoch: Epoch) -> Option<&[usize]> {
        self.get_cache(base_epoch)
            .map(|cache| cache.sync_committee_indices.as_slice())
    }
}
