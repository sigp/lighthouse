pub use participation_cache::ParticipationCache;
use types::{BeaconState, BeaconStateError, ChainSpec, EthSpec};

mod participation_cache;

pub struct EpochCache {
    pub total_active_balance: u64,
    pub participation: ParticipationCache,
}

impl EpochCache {
    pub fn new<T: EthSpec>(
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<Self, BeaconStateError> {
        Ok(Self {
            total_active_balance: state.get_total_active_balance(spec)?,
            participation: ParticipationCache::new(state, spec)?,
        })
    }
}
