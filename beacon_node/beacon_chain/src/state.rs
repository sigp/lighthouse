use crate::{BeaconChain, ClientDB, SlotClock};
use types::beacon_state::SlotProcessingError;

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    /// Advance the `self.state` `BeaconState` to the supplied slot.
    ///
    /// This will perform per_slot and per_epoch processing as required.
    ///
    /// The `previous_block_root` will be set to the root of the current head block (as determined
    /// by the fork-choice rule).
    pub fn advance_state(&self, slot: u64) -> Result<(), SlotProcessingError> {
        let state_slot = self.state.read().slot;
        let head_block_root = self.head().beacon_block_root;
        for _ in state_slot..slot {
            self.state
                .write()
                .per_slot_processing(head_block_root.clone(), &self.spec)?;
        }
        Ok(())
    }
}
