//! Garbage collection process that runs at start-up to clean up the database.
use crate::database::interface::BeaconNodeBackend;
use crate::hot_cold_store::HotColdDB;
use crate::StoreError as Error;
use crate::{DBColumn, KeyValueStore};
use slog::debug;
use types::{BeaconState, EthSpec, Hash256, Slot};

impl<E> HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>
where
    E: EthSpec,
{
    /// Clean up the database by performing one-off maintenance at start-up.
    pub fn remove_garbage(&self) -> Result<(), Error> {
        self.delete_temp_states()?;
        Ok(())
    }

    /// Delete the temporary states that were leftover by failed block imports.
    pub fn delete_temp_states(&self) -> Result<(), Error> {
        let mut ops = vec![];
        self.iter_temporary_state_roots().for_each(|state_root| {
            if let Ok(state_root) = state_root {
                ops.push(state_root);
            }
        });
        if !ops.is_empty() {
            debug!(
                self.log,
                "Garbage collecting {} temporary states",
                ops.len()
            );

            self.delete_batch(DBColumn::BeaconState, ops.clone())?;
            self.delete_batch(DBColumn::BeaconStateSummary, ops.clone())?;
            self.delete_batch(DBColumn::BeaconStateTemporary, ops)?;
        }

        Ok(())
    }
}

pub struct GarbageCollector<'a, E: EthSpec, Store: KeyValueStore<E>> {
    store: &'a Store,
    finalized_slot: Slot,
}

impl<'a, E: EthSpec, Store: KeyValueStore<E>> GarbageCollector<'a, E, Store> {
    pub fn new(store: &'a Store, finalized_slot: Slot) -> Self {
        Self {
            store,
            finalized_slot,
        }
    }

    pub fn collect_garbage(&self) -> Result<(), Error> {
        // Delete old blocks
        self.collect_old_blocks()?;

        // Delete old states
        self.collect_old_states()?;

        Ok(())
    }

    fn collect_old_blocks(&self) -> Result<(), Error> {
        let column = DBColumn::BeaconBlock;
        self.store.delete_if(column, |key| {
            let slot_bytes = key.get(0..8).ok_or(Error::InvalidKey)?;
            let slot = Slot::from_le_bytes(slot_bytes.try_into().map_err(|_| Error::InvalidKey)?);
            Ok(slot < self.finalized_slot)
        })
    }

    fn collect_old_states(&self) -> Result<(), Error> {
        let column = DBColumn::BeaconState;
        self.store.delete_if(column, |key| {
            let slot_bytes = key.get(0..8).ok_or(Error::InvalidKey)?;
            let slot = Slot::from_le_bytes(slot_bytes.try_into().map_err(|_| Error::InvalidKey)?);
            Ok(slot < self.finalized_slot)
        })
    }
}
