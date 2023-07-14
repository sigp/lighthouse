use crate::database::{self, Error as DbError};
use crate::updater::{Error, UpdateHandler};

use crate::block_packing::get_block_packing;

use eth2::types::{Epoch, EthSpec};
use log::{debug, error, warn};

const MAX_SIZE_SINGLE_REQUEST_BLOCK_PACKING: u64 = 50;

impl<T: EthSpec> UpdateHandler<T> {
    /// Forward fills the `block_packing` table starting from the entry with the
    /// highest slot.
    ///
    /// It constructs a request to the `get_block_packing` API with:
    /// `start_epoch` -> highest completely filled epoch + 1 (or epoch of lowest beacon block)
    /// `end_epoch` -> epoch of highest beacon block
    ///
    /// It will resync the latest epoch if it is not fully filled.
    /// That is, `if highest_filled_slot % slots_per_epoch != 31`
    /// This means that if the last slot of an epoch is a skip slot, the whole epoch will be
    //// resynced during the next head update.
    ///
    /// Request range will not exceed `MAX_SIZE_SINGLE_REQUEST_BLOCK_PACKING`.
    pub async fn fill_block_packing(&mut self) -> Result<(), Error> {
        let mut conn = database::get_connection(&self.pool)?;

        //  Get the slot of the highest entry in the `block_packing` table.
        let highest_filled_slot_opt = if self.config.block_packing {
            database::get_highest_block_packing(&mut conn)?.map(|packing| packing.slot)
        } else {
            return Err(Error::NotEnabled("block_packing".to_string()));
        };

        let mut start_epoch = if let Some(highest_filled_slot) = highest_filled_slot_opt {
            if highest_filled_slot.as_slot() % self.slots_per_epoch
                == self.slots_per_epoch.saturating_sub(1)
            {
                // The whole epoch is filled so we can begin syncing the next one.
                highest_filled_slot.as_slot().epoch(self.slots_per_epoch) + 1
            } else {
                // The epoch is only partially synced. Try to sync it fully.
                highest_filled_slot.as_slot().epoch(self.slots_per_epoch)
            }
        } else {
            // No entries in the `block_packing` table. Use `beacon_blocks` instead.
            if let Some(lowest_beacon_block) = database::get_lowest_beacon_block(&mut conn)? {
                lowest_beacon_block
                    .slot
                    .as_slot()
                    .epoch(self.slots_per_epoch)
            } else {
                // There are no blocks in the database, do not fill the `block_packing` table.
                warn!("Refusing to fill block packing as there are no blocks in the database");
                return Ok(());
            }
        };

        // The `get_block_packing` API endpoint cannot accept `start_epoch == 0`.
        if start_epoch == 0 {
            start_epoch += 1
        }

        if let Some(highest_block_slot) =
            database::get_highest_beacon_block(&mut conn)?.map(|block| block.slot.as_slot())
        {
            let mut end_epoch = highest_block_slot.epoch(self.slots_per_epoch);

            if start_epoch > end_epoch {
                debug!("Block packing is up to date with the head of the database");
                return Ok(());
            }

            // Ensure the size of the request does not exceed the maximum allowed value.
            if start_epoch < end_epoch.saturating_sub(MAX_SIZE_SINGLE_REQUEST_BLOCK_PACKING) {
                end_epoch = start_epoch + MAX_SIZE_SINGLE_REQUEST_BLOCK_PACKING
            }

            if let Some(lowest_block_slot) =
                database::get_lowest_beacon_block(&mut conn)?.map(|block| block.slot.as_slot())
            {
                let mut packing = get_block_packing(&self.bn, start_epoch, end_epoch).await?;

                // Since we pull a full epoch of data but are not guaranteed to have all blocks of
                // that epoch available, only insert blocks with corresponding `beacon_block`s.
                packing.retain(|packing| {
                    packing.slot.as_slot() >= lowest_block_slot
                        && packing.slot.as_slot() <= highest_block_slot
                });
                database::insert_batch_block_packing(&mut conn, packing)?;
            } else {
                return Err(Error::Database(DbError::Other(
                    "Database did not return a lowest block when one exists".to_string(),
                )));
            }
        } else {
            // There are no blocks in the `beacon_blocks` database, but there are entries in the
            // `block_packing` table. This is a critical failure. It usually means someone has
            // manually tampered with the database tables and should not occur during normal
            // operation.
            error!("Database is corrupted. Please re-sync the database");
            return Err(Error::Database(DbError::DatabaseCorrupted));
        }

        Ok(())
    }

    /// Backfill the `block_packing` table starting from the entry with the lowest slot.
    ///
    /// It constructs a request to the `get_block_packing` function with:
    /// `start_epoch` -> epoch of lowest_beacon_block
    /// `end_epoch` -> epoch of lowest filled `block_packing` - 1 (or epoch of highest beacon block)
    ///
    /// It will resync the lowest epoch if it is not fully filled.
    /// That is, `if lowest_filled_slot % slots_per_epoch != 0`
    /// This means that if the last slot of an epoch is a skip slot, the whole epoch will be
    //// resynced during the next head update.
    ///
    /// Request range will not exceed `MAX_SIZE_SINGLE_REQUEST_BLOCK_PACKING`.
    pub async fn backfill_block_packing(&mut self) -> Result<(), Error> {
        let mut conn = database::get_connection(&self.pool)?;
        let max_block_packing_backfill = self.config.max_backfill_size_epochs;

        // Get the slot of the lowest entry in the `block_packing` table.
        let lowest_filled_slot_opt = if self.config.block_packing {
            database::get_lowest_block_packing(&mut conn)?.map(|packing| packing.slot)
        } else {
            return Err(Error::NotEnabled("block_packing".to_string()));
        };

        let end_epoch = if let Some(lowest_filled_slot) = lowest_filled_slot_opt {
            if lowest_filled_slot.as_slot() % self.slots_per_epoch == 0 {
                lowest_filled_slot
                    .as_slot()
                    .epoch(self.slots_per_epoch)
                    .saturating_sub(Epoch::new(1))
            } else {
                // The epoch is only partially synced. Try to sync it fully.
                lowest_filled_slot.as_slot().epoch(self.slots_per_epoch)
            }
        } else {
            // No entries in the `block_packing` table. Use `beacon_blocks` instead.
            if let Some(highest_beacon_block) =
                database::get_highest_beacon_block(&mut conn)?.map(|block| block.slot)
            {
                highest_beacon_block.as_slot().epoch(self.slots_per_epoch)
            } else {
                // There are no blocks in the database, do not backfill the `block_packing` table.
                warn!("Refusing to backfill block packing as there are no blocks in the database");
                return Ok(());
            }
        };

        if end_epoch <= 1 {
            debug!("Block packing backfill is complete");
            return Ok(());
        }

        if let Some(lowest_block_slot) =
            database::get_lowest_beacon_block(&mut conn)?.map(|block| block.slot.as_slot())
        {
            let mut start_epoch = lowest_block_slot.epoch(self.slots_per_epoch);

            if start_epoch >= end_epoch {
                debug!("Block packing is up to date with the base of the database");
                return Ok(());
            }

            // Ensure that the request range does not exceed `max_block_packing_backfill` or
            // `MAX_SIZE_SINGLE_REQUEST_BLOCK_PACKING`.
            if start_epoch < end_epoch.saturating_sub(max_block_packing_backfill) {
                start_epoch = end_epoch.saturating_sub(max_block_packing_backfill)
            }
            if start_epoch < end_epoch.saturating_sub(MAX_SIZE_SINGLE_REQUEST_BLOCK_PACKING) {
                start_epoch = end_epoch.saturating_sub(MAX_SIZE_SINGLE_REQUEST_BLOCK_PACKING)
            }

            // The `block_packing` API cannot accept `start_epoch == 0`.
            if start_epoch == 0 {
                start_epoch += 1
            }

            if let Some(highest_block_slot) =
                database::get_highest_beacon_block(&mut conn)?.map(|block| block.slot.as_slot())
            {
                let mut packing = get_block_packing(&self.bn, start_epoch, end_epoch).await?;

                // Only insert blocks with corresponding `beacon_block`s.
                packing.retain(|packing| {
                    packing.slot.as_slot() >= lowest_block_slot
                        && packing.slot.as_slot() <= highest_block_slot
                });

                database::insert_batch_block_packing(&mut conn, packing)?;
            } else {
                return Err(Error::Database(DbError::Other(
                    "Database did not return a lowest block when one exists".to_string(),
                )));
            }
        } else {
            // There are no blocks in the `beacon_blocks` database, but there are entries in the
            // `block_packing` table. This is a critical failure. It usually means someone has
            // manually tampered with the database tables and should not occur during normal
            // operation.
            error!("Database is corrupted. Please re-sync the database");
            return Err(Error::Database(DbError::DatabaseCorrupted));
        }

        Ok(())
    }
}
