use crate::database::{self, Error as DbError};
use crate::updater::{Error, UpdateHandler};

use eth2::types::EthSpec;
use log::{debug, error, warn};

const MAX_SIZE_SINGLE_REQUEST_BLOCKPRINT: u64 = 1600;

impl<T: EthSpec> UpdateHandler<T> {
    /// Forward fills the `blockprint` table starting from the entry with the
    /// highest slot.
    ///
    /// It constructs a request to the `get_blockprint` API with:
    /// `start_slot` -> highest filled `blockprint` + 1 (or lowest beacon block)
    /// `end_slot` -> highest beacon block
    ///
    /// Request range will not exceed `MAX_SIZE_SINGLE_REQUEST_BLOCKPRINT`.
    pub async fn fill_blockprint(&mut self) -> Result<(), Error> {
        // Ensure blockprint in enabled.
        if let Some(blockprint_client) = &self.blockprint {
            let mut conn = database::get_connection(&self.pool)?;

            //  Get the slot of the highest entry in the `blockprint` table.
            let mut start_slot = if let Some(highest_filled_slot) =
                database::get_highest_blockprint(&mut conn)?.map(|print| print.slot)
            {
                highest_filled_slot.as_slot() + 1
            } else {
                // No entries in the `blockprint` table. Use `beacon_blocks` instead.
                if let Some(lowest_beacon_block) =
                    database::get_lowest_beacon_block(&mut conn)?.map(|block| block.slot)
                {
                    lowest_beacon_block.as_slot()
                } else {
                    // There are no blocks in the database, do not fill the `blockprint` table.
                    warn!("Refusing to fill blockprint as there are no blocks in the database");
                    return Ok(());
                }
            };

            // The `blockprint` API cannot accept `start_slot == 0`.
            if start_slot == 0 {
                start_slot += 1;
            }

            if let Some(highest_beacon_block) =
                database::get_highest_beacon_block(&mut conn)?.map(|block| block.slot)
            {
                let mut end_slot = highest_beacon_block.as_slot();

                if start_slot > end_slot {
                    debug!("Blockprint is up to date with the head of the database");
                    return Ok(());
                }

                // Ensure the size of the request does not exceed the maximum allowed value.
                if start_slot < end_slot.saturating_sub(MAX_SIZE_SINGLE_REQUEST_BLOCKPRINT) {
                    end_slot = start_slot + MAX_SIZE_SINGLE_REQUEST_BLOCKPRINT
                }

                let mut prints = blockprint_client
                    .get_blockprint(start_slot, end_slot)
                    .await?;

                // Ensure the prints returned from blockprint are for slots which exist in the
                // `beacon_blocks` table.
                prints.retain(|print| {
                    database::get_beacon_block_by_slot(&mut conn, print.slot)
                        .ok()
                        .flatten()
                        .is_some()
                });

                database::insert_batch_blockprint(&mut conn, prints)?;
            } else {
                // There are no blocks in the `beacon_blocks` database, but there are entries in either
                // `blockprint` table. This is a critical failure. It usually means
                // someone has manually tampered with the database tables and should not occur during
                // normal operation.
                error!("Database is corrupted. Please re-sync the database");
                return Err(Error::Database(DbError::DatabaseCorrupted));
            }
        }

        Ok(())
    }

    /// Backfill the `blockprint` table starting from the entry with the lowest slot.
    ///
    /// It constructs a request to the `get_blockprint` API with:
    /// `start_slot` -> lowest_beacon_block
    /// `end_slot` -> lowest filled `blockprint` - 1 (or highest beacon block)
    ///
    /// Request range will not exceed `MAX_SIZE_SINGLE_REQUEST_BLOCKPRINT`.
    pub async fn backfill_blockprint(&mut self) -> Result<(), Error> {
        // Ensure blockprint in enabled.
        if let Some(blockprint_client) = &self.blockprint {
            let mut conn = database::get_connection(&self.pool)?;
            let max_blockprint_backfill =
                self.config.max_backfill_size_epochs * self.slots_per_epoch;

            // Get the slot of the lowest entry in the `blockprint` table.
            let end_slot = if let Some(lowest_filled_slot) =
                database::get_lowest_blockprint(&mut conn)?.map(|print| print.slot)
            {
                lowest_filled_slot.as_slot().saturating_sub(1_u64)
            } else {
                // No entries in the `blockprint` table. Use `beacon_blocks` instead.
                if let Some(highest_beacon_block) =
                    database::get_highest_beacon_block(&mut conn)?.map(|block| block.slot)
                {
                    highest_beacon_block.as_slot()
                } else {
                    // There are no blocks in the database, do not backfill the `blockprint` table.
                    warn!("Refusing to backfill blockprint as there are no blocks in the database");
                    return Ok(());
                }
            };

            if end_slot <= 1 {
                debug!("Blockprint backfill is complete");
                return Ok(());
            }

            if let Some(lowest_block_slot) = database::get_lowest_beacon_block(&mut conn)? {
                let mut start_slot = lowest_block_slot.slot.as_slot();

                if start_slot >= end_slot {
                    debug!("Blockprint are up to date with the base of the database");
                    return Ok(());
                }

                // Ensure that the request range does not exceed `max_blockprint_backfill` or
                // `MAX_SIZE_SINGLE_REQUEST_BLOCKPRINT`.
                if start_slot < end_slot.saturating_sub(max_blockprint_backfill) {
                    start_slot = end_slot.saturating_sub(max_blockprint_backfill)
                }

                if start_slot < end_slot.saturating_sub(MAX_SIZE_SINGLE_REQUEST_BLOCKPRINT) {
                    start_slot = end_slot.saturating_sub(MAX_SIZE_SINGLE_REQUEST_BLOCKPRINT)
                }

                // The `blockprint` API cannot accept `start_slot == 0`.
                if start_slot == 0 {
                    start_slot += 1
                }

                let mut prints = blockprint_client
                    .get_blockprint(start_slot, end_slot)
                    .await?;

                // Ensure the prints returned from blockprint are for slots which exist in the
                // `beacon_blocks` table.
                prints.retain(|print| {
                    database::get_beacon_block_by_slot(&mut conn, print.slot)
                        .ok()
                        .flatten()
                        .is_some()
                });

                database::insert_batch_blockprint(&mut conn, prints)?;
            } else {
                // There are no blocks in the `beacon_blocks` database, but there are entries in the `blockprint`
                // table. This is a critical failure. It usually means someone has manually tampered with the
                // database tables and should not occur during normal operation.
                error!("Database is corrupted. Please re-sync the database");
                return Err(Error::Database(DbError::DatabaseCorrupted));
            }
        }
        Ok(())
    }
}
