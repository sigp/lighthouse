use crate::{BeaconChain, CheckPoint, ClientDB, SlotClock};
use std::sync::RwLockReadGuard;
use types::{BeaconBlock, BeaconState, Hash256};

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    pub fn update_finalized_head(
        &self,
        new_beacon_block: BeaconBlock,
        new_beacon_block_root: Hash256,
        new_beacon_state: BeaconState,
        new_beacon_state_root: Hash256,
    ) {
        let mut finalized_head = self
            .finalized_head
            .write()
            .expect("CRITICAL: finalized_head poisioned.");
        finalized_head.update(
            new_beacon_block,
            new_beacon_block_root,
            new_beacon_state,
            new_beacon_state_root,
        );
    }

    pub fn finalized_head(&self) -> RwLockReadGuard<CheckPoint> {
        self.finalized_head
            .read()
            .expect("CRITICAL: finalized_head poisioned.")
    }
}
