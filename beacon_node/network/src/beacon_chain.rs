use beacon_chain::BeaconChain as RawBeaconChain;
use beacon_chain::{
    db::ClientDB,
    fork_choice::ForkChoice,
    parking_lot::RwLockReadGuard,
    slot_clock::SlotClock,
    types::{BeaconState, ChainSpec},
    CheckPoint,
};
use eth2_libp2p::HelloMessage;
use types::{Epoch, Hash256, Slot};

/// The network's API to the beacon chain.
pub trait BeaconChain: Send + Sync {
    fn get_spec(&self) -> &ChainSpec;

    fn get_state(&self) -> RwLockReadGuard<BeaconState>;

    fn slot(&self) -> Slot;

    fn head(&self) -> RwLockReadGuard<CheckPoint>;

    fn best_slot(&self) -> Slot;

    fn best_block_root(&self) -> Hash256;

    fn finalized_head(&self) -> RwLockReadGuard<CheckPoint>;

    fn finalized_epoch(&self) -> Epoch;

    fn hello_message(&self) -> HelloMessage;
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

    fn get_state(&self) -> RwLockReadGuard<BeaconState> {
        self.state.read()
    }

    fn slot(&self) -> Slot {
        self.get_state().slot
    }

    fn head(&self) -> RwLockReadGuard<CheckPoint> {
        self.head()
    }

    fn finalized_epoch(&self) -> Epoch {
        self.get_state().finalized_epoch
    }

    fn finalized_head(&self) -> RwLockReadGuard<CheckPoint> {
        self.finalized_head()
    }

    fn best_slot(&self) -> Slot {
        self.head().beacon_block.slot
    }

    fn best_block_root(&self) -> Hash256 {
        self.head().beacon_block_root
    }

    fn hello_message(&self) -> HelloMessage {
        let spec = self.get_spec();
        let state = self.get_state();

        HelloMessage {
            network_id: spec.network_id,
            latest_finalized_root: state.finalized_root,
            latest_finalized_epoch: state.finalized_epoch,
            best_root: self.best_block_root(),
            best_slot: self.best_slot(),
        }
    }
}
