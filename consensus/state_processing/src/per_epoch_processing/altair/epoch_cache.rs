pub use participation_cache::ParticipationCache;
use types::{BeaconState, BeaconStateError, ChainSpec, EthSpec};

mod participation_cache;

pub struct EpochCache {
    pub participation: ParticipationCache,
}

impl EpochCache {
    pub fn new<T: EthSpec>(
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<Self, BeaconStateError> {
        Ok(Self {
            participation: ParticipationCache::new(state, spec)?,
        })
    }
}
