use super::{BeaconChain, ClientDB, SlotClock};
use types::{AttestationData, Hash256};

#[derive(Debug, PartialEq)]
pub enum Error {
    SlotTooOld,
    PresentSlotUnknown,
    StateError,
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    pub fn produce_attestation_data(&self, shard: u64) -> Result<AttestationData, Error> {
        let justified_slot = self.justified_slot();
        let justified_block_root = self
            .state
            .read()
            .get_block_root(justified_slot, &self.spec)
            .ok_or_else(|| Error::SlotTooOld)?
            .clone();

        let epoch_boundary_root = self
            .state
            .read()
            .get_block_root(
                self.state.read().current_epoch_start_slot(&self.spec),
                &self.spec,
            )
            .ok_or_else(|| Error::SlotTooOld)?
            .clone();

        Ok(AttestationData {
            slot: self.state.read().slot,
            shard,
            beacon_block_root: self.head().beacon_block_root.clone(),
            epoch_boundary_root,
            shard_block_root: Hash256::zero(),
            latest_crosslink_root: Hash256::zero(),
            justified_slot,
            justified_block_root,
        })
    }
}
