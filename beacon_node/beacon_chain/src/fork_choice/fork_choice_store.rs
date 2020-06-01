use crate::{BeaconChainTypes, BeaconSnapshot};
use lmd_ghost::ForkChoiceStore as StoreTrait;
use slot_clock::SlotClock;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use store::iter::{BlockRootsIterator, ReverseBlockRootIterator};
use types::{BeaconState, ChainSpec, Checkpoint, Hash256, Slot};

#[derive(Debug, PartialEq)]
pub enum Error {
    UnableToReadSlot,
    InvalidGenesisSnapshot(Slot),
    AncestorUnknown(Hash256),
    UninitializedBestJustifiedBalances,
    InvalidPersistedBytes(ssz::DecodeError),
}

#[derive(Debug)]
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

impl<T: BeaconChainTypes> PartialEq for ForkChoiceStore<T> {
    /// This implementation ignores the `store` and `slot_clock`.
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
            && self.finalized_checkpoint == other.finalized_checkpoint
            && self.justified_checkpoint == other.justified_checkpoint
            && self.justified_balances == other.justified_balances
            && self.best_justified_checkpoint == other.best_justified_checkpoint
            && self.best_justified_balances == other.best_justified_balances
    }
}

impl<T: BeaconChainTypes> ForkChoiceStore<T> {
    pub fn from_genesis(
        store: Arc<T::Store>,
        slot_clock: T::SlotClock,
        genesis: &BeaconSnapshot<T::EthSpec>,
        spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let time = slot_clock.now().ok_or_else(|| Error::UnableToReadSlot)?;

        if genesis.beacon_state.slot != spec.genesis_slot {
            return Err(Error::InvalidGenesisSnapshot(genesis.beacon_state.slot));
        }

        Ok(Self {
            store,
            slot_clock,
            time,
            finalized_checkpoint: genesis.beacon_state.finalized_checkpoint,
            justified_checkpoint: genesis.beacon_state.current_justified_checkpoint,
            justified_balances: genesis.beacon_state.balances.clone().into(),
            best_justified_checkpoint: genesis.beacon_state.current_justified_checkpoint,
            best_justified_balances: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        PersistedForkChoiceStore::from(self).as_ssz_bytes()
    }

    pub fn from_bytes(
        bytes: &[u8],
        store: Arc<T::Store>,
        slot_clock: T::SlotClock,
    ) -> Result<Self, Error> {
        let persisted = PersistedForkChoiceStore::from_ssz_bytes(bytes)
            .map_err(Error::InvalidPersistedBytes)?;

        Ok(Self {
            store,
            slot_clock,
            time: persisted.time,
            finalized_checkpoint: persisted.finalized_checkpoint,
            justified_checkpoint: persisted.justified_checkpoint,
            justified_balances: persisted.justified_balances,
            best_justified_checkpoint: persisted.best_justified_checkpoint,
            best_justified_balances: persisted.best_justified_balances,
        })
    }
}

impl<T: BeaconChainTypes> StoreTrait<T::EthSpec> for ForkChoiceStore<T> {
    type Error = Error;

    fn update_time(&mut self) -> Result<(), Error> {
        loop {
            let time = self
                .slot_clock
                .now()
                .ok_or_else(|| Error::UnableToReadSlot)?;

            if self.time < time {
                self.on_tick(time)?;
            } else {
                break Ok(());
            }
        }
    }

    fn get_current_slot(&self) -> Slot {
        self.time
    }

    fn set_current_slot(&mut self, slot: Slot) {
        self.time = slot
    }

    fn set_justified_checkpoint_to_best_justified_checkpoint(&mut self) -> Result<(), Error> {
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

    fn justified_checkpoint(&self) -> &Checkpoint {
        &self.justified_checkpoint
    }

    fn justified_balances(&self) -> &[u64] {
        &self.justified_balances
    }

    fn best_justified_checkpoint(&self) -> &Checkpoint {
        &self.best_justified_checkpoint
    }

    fn finalized_checkpoint(&self) -> &Checkpoint {
        &self.finalized_checkpoint
    }

    fn set_finalized_checkpoint(&mut self, c: Checkpoint) {
        self.finalized_checkpoint = c
    }

    fn set_justified_checkpoint(&mut self, state: &BeaconState<T::EthSpec>) {
        self.justified_checkpoint = state.current_justified_checkpoint;
        self.justified_balances = state.balances.clone().into();
    }

    fn set_best_justified_checkpoint(&mut self, state: &BeaconState<T::EthSpec>) {
        self.best_justified_checkpoint = state.current_justified_checkpoint;
        self.best_justified_balances = Some(state.balances.clone().into());
    }

    fn get_ancestor(
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

#[derive(Encode, Decode)]
pub struct PersistedForkChoiceStore {
    time: Slot,
    finalized_checkpoint: Checkpoint,
    justified_checkpoint: Checkpoint,
    justified_balances: Vec<u64>,
    best_justified_checkpoint: Checkpoint,
    best_justified_balances: Option<Vec<u64>>,
}

impl<T: BeaconChainTypes> From<&ForkChoiceStore<T>> for PersistedForkChoiceStore {
    fn from(store: &ForkChoiceStore<T>) -> Self {
        Self {
            time: store.time,
            finalized_checkpoint: store.finalized_checkpoint,
            justified_checkpoint: store.justified_checkpoint,
            justified_balances: store.justified_balances.clone(),
            best_justified_checkpoint: store.best_justified_checkpoint,
            best_justified_balances: store.best_justified_balances.clone(),
        }
    }
}
