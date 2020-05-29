use crate::fork_choice::compute_slots_since_epoch_start;
use types::{BeaconState, Checkpoint, EthSpec, Hash256, Slot};

pub trait ForkChoiceStore<T: EthSpec>: Sized {
    type Error;

    fn update_time(&mut self) -> Result<(), Self::Error>;

    fn on_tick(&mut self, time: Slot) -> Result<(), Self::Error> {
        let store = self;

        let previous_slot = store.get_current_slot();

        // Update store time.
        store.set_current_slot(time);

        let current_slot = store.get_current_slot();
        if !(current_slot > previous_slot
            && compute_slots_since_epoch_start::<T>(current_slot) == 0)
        {
            return Ok(());
        }

        if store.best_justified_checkpoint().epoch > store.justified_checkpoint().epoch {
            store.set_justified_checkpoint_to_best_justified_checkpoint()?;
        }

        Ok(())
    }

    fn get_current_slot(&self) -> Slot;

    fn set_current_slot(&mut self, slot: Slot);

    fn set_justified_checkpoint_to_best_justified_checkpoint(&mut self) -> Result<(), Self::Error>;

    fn justified_checkpoint(&self) -> &Checkpoint;

    fn justified_balances(&self) -> &[u64];

    fn best_justified_checkpoint(&self) -> &Checkpoint;

    fn finalized_checkpoint(&self) -> &Checkpoint;

    fn set_finalized_checkpoint(&mut self, c: Checkpoint);

    fn set_justified_checkpoint(&mut self, state: &BeaconState<T>);

    fn set_best_justified_checkpoint(&mut self, state: &BeaconState<T>);

    fn get_ancestor(
        &self,
        state: &BeaconState<T>,
        root: Hash256,
        slot: Slot,
    ) -> Result<Hash256, Self::Error>;

    fn as_bytes(&self) -> Vec<u8>;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>;
}
