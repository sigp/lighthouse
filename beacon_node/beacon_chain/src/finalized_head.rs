use crate::{BeaconChain, CheckPoint, ClientDB, SlotClock};
use parking_lot::RwLockReadGuard;
use types::{BeaconBlock, BeaconState, Hash256};

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    /// Update the justified head to some new values.
    pub fn update_finalized_head(
        &self,
        new_beacon_block: BeaconBlock,
        new_beacon_block_root: Hash256,
        new_beacon_state: BeaconState,
        new_beacon_state_root: Hash256,
    ) {
        let mut finalized_head = self.finalized_head.write();
        finalized_head.update(
            new_beacon_block,
            new_beacon_block_root,
            new_beacon_state,
            new_beacon_state_root,
        );
    }

    /// Returns a read-lock guarded `CheckPoint` struct for reading the justified head (as chosen,
    /// indirectly,  by the fork-choice rule).
    pub fn finalized_head(&self) -> RwLockReadGuard<CheckPoint> {
        self.finalized_head.read()
    }
}
