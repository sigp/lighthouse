use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use proto_array_fork_choice::{core::ProtoArray, Error as ProtoArrayError, ProtoArrayForkChoice};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::marker::PhantomData;
use types::{BeaconBlock, BeaconState, Checkpoint, Epoch, EthSpec, Hash256, Slot};

const SAFE_SLOTS_TO_UPDATE_JUSTIFIED: u64 = 8;

pub enum Error {
    UnableToReadSlot,
    AncestorUnknown(Hash256),
    // TODO: make this an actual error enum.
    ProtoArrayError(String),
    BeaconChainError(Box<BeaconChainError>),
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Error {
        Error::BeaconChainError(Box::new(e))
    }
}

impl From<String> for Error {
    fn from(e: String) -> Error {
        Error::ProtoArrayError(e)
    }
}

type Balances = Vec<u64>;
type BalancesCache = HashMap<Hash256, (Epoch, Balances)>;

pub struct ForkChoiceStore<T: BeaconChainTypes> {
    chain: BeaconChain<T>,
    slot_clock: T::SlotClock,
    time: Slot,
    finalized_checkpoint: Checkpoint,
    justified_checkpoint: Checkpoint,
    best_justified_checkpoint: Checkpoint,
    balances: BalancesCache,
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
}

pub fn get_current_slot<T: BeaconChainTypes>(store: &ForkChoiceStore<T>) -> Slot {
    store.time
}

pub fn on_tick<T: BeaconChainTypes>(
    store: &mut ForkChoiceStore<T>,
    time: Slot,
) -> Result<(), Error> {
    let previous_slot = get_current_slot(store);

    // Update store time.
    store.time = time;

    let current_slot = get_current_slot(store);
    if !(current_slot > previous_slot
        && compute_slots_since_epoch_start::<T::EthSpec>(current_slot) == 0)
    {
        return Ok(());
    }

    if store.best_justified_checkpoint.epoch > store.justified_checkpoint.epoch {
        store.justified_checkpoint = store.best_justified_checkpoint
    }

    Ok(())
}

fn should_update_justified_checkpoint<T: BeaconChainTypes>(
    store: &ForkChoiceStore<T>,
    state: &BeaconState<T::EthSpec>,
) -> Result<bool, Error> {
    let new_justified_checkpoint = &state.current_justified_checkpoint;

    if compute_slots_since_epoch_start::<T::EthSpec>(get_current_slot(store))
        < SAFE_SLOTS_TO_UPDATE_JUSTIFIED
    {
        return Ok(true);
    }

    let justified_slot =
        compute_start_slot_at_epoch::<T::EthSpec>(store.justified_checkpoint.epoch);
    if get_ancestor(store, state, new_justified_checkpoint.root, justified_slot)?
        != store.justified_checkpoint.root
    {
        return Ok(false);
    }

    Ok(true)
}

fn get_ancestor<T: BeaconChainTypes>(
    store: &ForkChoiceStore<T>,
    state: &BeaconState<T::EthSpec>,
    root: Hash256,
    slot: Slot,
) -> Result<Hash256, Error> {
    let root = match state.get_block_root(slot) {
        Ok(root) => *root,
        Err(_) => store
            .chain
            .get_ancestor_block_root(root, slot)?
            .ok_or_else(|| Error::AncestorUnknown(root))?,
    };

    Ok(root)
}

/// Calculate how far `slot` lies from the start of its epoch.
fn compute_slots_since_epoch_start<E: EthSpec>(slot: Slot) -> Slot {
    slot - slot
        .epoch(E::slots_per_epoch())
        .start_slot(E::slots_per_epoch())
}

fn compute_start_slot_at_epoch<E: EthSpec>(epoch: Epoch) -> Slot {
    epoch.start_slot(E::slots_per_epoch())
}

pub struct ForkChoice<T: BeaconChainTypes> {
    /// Storage for `ForkChoice`, modelled off the specs `Store` object.
    fc_store: ForkChoiceStore<T>,
    /// The underlying representation of the block DAG.
    proto_array: ProtoArrayForkChoice,
    /// Used for resolving the `0x00..00` alias back to genesis.
    ///
    /// Does not necessarily need to be the _actual_ genesis, it suffices to be the finalized root
    /// whenever the struct was instantiated.
    genesis_block_root: Hash256,
    _phantom: PhantomData<T>,
}

impl<T: BeaconChainTypes> ForkChoice<T> {
    pub fn on_block(
        &mut self,
        block: &BeaconBlock<T::EthSpec>,
        block_root: Hash256,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<(), Error> {
        let store = &mut self.fc_store;
        store.update_time()?;

        // TODO: stuff here
        if state.current_justified_checkpoint.epoch > store.justified_checkpoint.epoch {
            if state.current_justified_checkpoint.epoch > store.best_justified_checkpoint.epoch {
                store.best_justified_checkpoint = state.current_justified_checkpoint;
            }
            if should_update_justified_checkpoint(store, state)? {
                store.justified_checkpoint = state.current_justified_checkpoint;
            }
        }

        if state.finalized_checkpoint.epoch > store.finalized_checkpoint.epoch {
            store.finalized_checkpoint = state.finalized_checkpoint;
            let finalized_slot =
                compute_start_slot_at_epoch::<T::EthSpec>(store.finalized_checkpoint.epoch);

            if state.current_justified_checkpoint.epoch > store.justified_checkpoint.epoch
                || get_ancestor(
                    store,
                    state,
                    store.justified_checkpoint.root,
                    finalized_slot,
                )? != store.finalized_checkpoint.root
            {
                store.justified_checkpoint = state.current_justified_checkpoint;
            }
        }

        // This does not apply a vote to the block, it just makes fork choice aware of the block so
        // it can still be identified as the head even if it doesn't have any votes.
        self.proto_array.process_block(
            block.slot,
            block_root,
            block.parent_root,
            block.state_root,
            state.current_justified_checkpoint.epoch,
            state.finalized_checkpoint.epoch,
        )?;

        Ok(())
    }
}
