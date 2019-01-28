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
    pub fn produce_attestation_data(
        &self,
        slot: u64,
        shard: u64,
    ) -> Result<AttestationData, Error> {
        let present_slot = self
            .present_slot()
            .ok_or_else(|| Error::PresentSlotUnknown)?;
        let state = self.state(present_slot).map_err(|_| Error::StateError)?;

        let justified_slot = self.justified_slot();

        let justified_block_root = *state
            .get_block_root(justified_slot, &self.spec)
            .ok_or_else(|| Error::SlotTooOld)?;

        let head_slot = self.head().beacon_block.slot;
        let epoch_boundary_root = *state
            .get_block_root(head_slot % self.spec.epoch_length, &self.spec)
            .ok_or_else(|| Error::SlotTooOld)?;

        Ok(AttestationData {
            slot,
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
