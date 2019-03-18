use beacon_chain::BeaconChain as RawBeaconChain;
use beacon_chain::{
    db::ClientDB, fork_choice::ForkChoice, parking_lot::RwLockReadGuard, slot_clock::SlotClock,
    types::ChainSpec, CheckPoint,
};

/// The network's API to the beacon chain.
pub trait BeaconChain: Send + Sync {
    fn get_spec(&self) -> &ChainSpec;

    fn head(&self) -> RwLockReadGuard<CheckPoint>;

    fn finalized_head(&self) -> RwLockReadGuard<CheckPoint>;
}

impl<T, U, F> BeaconChain for RawBeaconChain<T, U, F>
where
    T: ClientDB + Sized,
    U: SlotClock,
    F: ForkChoice,
{
    fn get_spec(&self) -> &ChainSpec {
        &self.spec
    }

    fn head(&self) -> RwLockReadGuard<CheckPoint> {
        self.head()
    }

    fn finalized_head(&self) -> RwLockReadGuard<CheckPoint> {
        self.finalized_head()
    }
}
