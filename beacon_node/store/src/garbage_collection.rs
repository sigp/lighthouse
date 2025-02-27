//! Garbage collection process that runs at start-up to clean up the database.
use crate::database::interface::BeaconNodeBackend;
use crate::hot_cold_store::HotColdDB;
use crate::{DBColumn, Error};
use slog::debug;
use types::EthSpec;

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
