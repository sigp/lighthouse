use super::{on_tick, Error};
use crate::BeaconChainTypes;
use slot_clock::SlotClock;
use std::sync::Arc;
use store::iter::{BlockRootsIterator, ReverseBlockRootIterator};
use types::{BeaconState, Checkpoint, Hash256, Slot};

pub struct ForkChoiceStore<T: BeaconChainTypes> {
    store: Arc<T::Store>,
    slot_clock: T::SlotClock,
    time: Slot,
    finalized_checkpoint: Checkpoint,
    justified_checkpoint: Checkpoint,
    justified_balances: Vec<u64>,
    best_justified_checkpoint: Checkpoint,
    best_justified_balances: Option<Vec<u64>>,
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

    pub fn time(&self) -> Slot {
        self.time
    }

    pub fn set_time(&mut self, slot: Slot) {
        self.time = slot
    }

    pub fn set_justified_checkpoint_to_best_justified_checkpoint(&mut self) -> Result<(), Error> {
        if self.best_justified_balances.is_some() {
            self.justified_checkpoint = self.best_justified_checkpoint;
            self.justified_balances = self
                .best_justified_balances
                .take()
                .expect("protected by prior if statement");

            Ok(())
        } else {
            Err(Error::UninitializedBestJustifiedBalances)
        }
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

    pub fn set_finalized_checkpoint(&mut self, c: Checkpoint) {
        self.finalized_checkpoint = c
    }

    pub fn set_justified_checkpoint(&mut self, state: &BeaconState<T::EthSpec>) {
        self.justified_checkpoint = state.current_justified_checkpoint;
        self.justified_balances = state.balances.clone().into();
    }

    pub fn set_best_justified_checkpoint(&mut self, state: &BeaconState<T::EthSpec>) {
        self.best_justified_checkpoint = state.current_justified_checkpoint;
        self.best_justified_balances = Some(state.balances.clone().into());
    }

    pub fn get_ancestor(
        &self,
        state: &BeaconState<T::EthSpec>,
        root: Hash256,
        slot: Slot,
    ) -> Result<Hash256, Error> {
        let root = match state.get_block_root(slot) {
            Ok(root) => *root,
            Err(_) => {
                let start_slot = state.slot;

                let iter = BlockRootsIterator::owned(self.store.clone(), state.clone());

                ReverseBlockRootIterator::new((root, start_slot), iter)
                    .find(|(_, ancestor_slot)| *ancestor_slot == slot)
                    .map(|(ancestor_block_root, _)| ancestor_block_root)
                    .ok_or_else(|| Error::AncestorUnknown(root))?
            }
        };

        Ok(root)
    }
}
