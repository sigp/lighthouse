use super::{on_tick, Error};
use crate::{metrics, BeaconChain, BeaconChainError, BeaconChainTypes};
use slot_clock::SlotClock;
use types::{
    BeaconBlock, BeaconState, Checkpoint, Epoch, EthSpec, Hash256, IndexedAttestation, Slot,
};

pub struct ForkChoiceStore<T: BeaconChainTypes> {
    chain: BeaconChain<T>,
    slot_clock: T::SlotClock,
    time: Slot,
    finalized_checkpoint: Checkpoint,
    justified_checkpoint: Checkpoint,
    justified_balances: Vec<u64>,
    best_justified_checkpoint: Checkpoint,
    best_justified_balances: Vec<u64>,
}

impl<T: BeaconChainTypes> ForkChoiceStore<T> {
    pub fn update_time(&mut self) -> Result<(), Error> {
        loop {
            let time = self
                .slot_clock
                .now()
                .ok_or_else(|| Error::UnableToReadSlot)?;

            if self.time < time {
                on_tick(self, time)?;
            } else {
                break Ok(());
            }
        }
    }

    pub fn chain(&self) -> &BeaconChain<T> {
        &self.chain
    }

    pub fn time(&mut self) -> &mut Slot {
        &mut self.time
    }

    pub fn set_justified_checkpoint_to_best_justified_checkpoint(&mut self) {
        todo!()
    }

    pub fn justified_checkpoint(&self) -> &Checkpoint {
        &self.justified_checkpoint
    }

    pub fn justified_balances(&self) -> &[u64] {
        &self.justified_balances
    }

    pub fn best_justified_checkpoint(&self) -> &Checkpoint {
        &self.best_justified_checkpoint
    }

    pub fn finalized_checkpoint(&self) -> &Checkpoint {
        &self.finalized_checkpoint
    }
}
