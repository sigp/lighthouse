use crate::{BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec, SyncCommittee};

#[derive(Debug, Default, PartialEq, Clone)]
pub struct SyncCommitteeCache<T: EthSpec> {
    cache: Option<Cache<T>>,
}

#[derive(Debug, PartialEq, Clone)]
struct Cache<T: EthSpec> {
    base_epoch: Epoch,
    sync_committee_indices: Vec<usize>,
    sync_committee: SyncCommittee<T>,
}

impl<T: EthSpec> SyncCommitteeCache<T> {
    pub fn new(state: &BeaconState<T>, spec: &ChainSpec) -> Result<Self, BeaconStateError> {
        let base_epoch = state.sync_committee_base_epoch(spec)?;
        let sync_committee_indices = state.compute_sync_committee_indices(spec)?;
        let sync_committee = state.compute_sync_committee(&sync_committee_indices)?;
        Ok(SyncCommitteeCache {
            cache: Some(Cache {
                base_epoch,
                sync_committee_indices,
                sync_committee,
            }),
        })
    }

    pub fn is_initialized_for(&self, base_epoch: Epoch) -> bool {
        self.get_cache(base_epoch).is_some()
    }

    fn get_cache(&self, base_epoch: Epoch) -> Option<&Cache<T>> {
        self.cache
            .as_ref()
            .filter(|cache| cache.base_epoch == base_epoch)
    }

    pub fn get_sync_committee_indices(&self, base_epoch: Epoch) -> Option<&[usize]> {
        self.get_cache(base_epoch)
            .map(|cache| cache.sync_committee_indices.as_slice())
    }

    pub fn get_sync_committee(&self, base_epoch: Epoch) -> Option<&SyncCommittee<T>> {
        self.get_cache(base_epoch)
            .map(|cache| &cache.sync_committee)
    }
}
