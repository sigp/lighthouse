use crate::common::update_progressive_balances_cache::initialize_progressive_balances_cache;
use crate::epoch_cache::initialize_epoch_cache;
use types::{BeaconState, ChainSpec, EpochCacheError, EthSpec, Hash256, RelativeEpoch};

/// Mixin trait for the beacon state that provides operations on *all* caches.
///
/// The reason this trait exists here away from `BeaconState` itself is that some caches are
/// computed by functions in `state_processing`.
pub trait AllCaches {
    /// Build all caches.
    ///
    /// Note that this excludes milhouse's intrinsic tree-hash cache. That needs to be managed
    /// separately.
    fn build_all_caches(&mut self, spec: &ChainSpec) -> Result<(), EpochCacheError>;

    /// Return true if all caches are built.
    ///
    /// Note that this excludes milhouse's intrinsic tree-hash cache. That needs to be managed
    /// separately.
    fn all_caches_built(&self) -> bool;
}

impl<E: EthSpec> AllCaches for BeaconState<E> {
    fn build_all_caches(&mut self, spec: &ChainSpec) -> Result<(), EpochCacheError> {
        self.build_caches(spec)?;
        initialize_epoch_cache(self, spec)?;
        initialize_progressive_balances_cache(self, spec)?;
        Ok(())
    }

    fn all_caches_built(&self) -> bool {
        let current_epoch = self.current_epoch();
        let Ok(epoch_cache_decision_block_root) =
            self.proposer_shuffling_decision_root(Hash256::zero())
        else {
            return false;
        };
        self.get_total_active_balance_at_epoch(current_epoch)
            .is_ok()
            && self.committee_cache_is_initialized(RelativeEpoch::Previous)
            && self.committee_cache_is_initialized(RelativeEpoch::Current)
            && self.committee_cache_is_initialized(RelativeEpoch::Next)
            && self
                .progressive_balances_cache()
                .is_initialized_at(current_epoch)
            && self.pubkey_cache().len() == self.validators().len()
            && self.exit_cache().check_initialized().is_ok()
            && self.slashings_cache_is_initialized()
            && self
                .epoch_cache()
                .check_validity(current_epoch, epoch_cache_decision_block_root)
                .is_ok()
    }
}
