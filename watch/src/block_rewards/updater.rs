use crate::database::{self, Error as DbError};
use crate::updater::{Error, UpdateHandler};

use crate::block_rewards::get_block_rewards;

use eth2::types::EthSpec;
use log::{debug, error, warn};

const MAX_SIZE_SINGLE_REQUEST_BLOCK_REWARDS: u64 = 1600;

impl<T: EthSpec> UpdateHandler<T> {
    /// Forward fills the `block_rewards` table starting from the entry with the
    /// highest slot.
    ///
    /// It constructs a request to the `get_block_rewards` API with:
    /// `start_slot` -> highest filled `block_rewards` + 1 (or lowest beacon block)
    /// `end_slot` -> highest beacon block
    ///
    /// Request range will not exceed `MAX_SIZE_SINGLE_REQUEST_BLOCK_REWARDS`.
    pub async fn fill_block_rewards(&mut self) -> Result<(), Error> {
        let mut conn = database::get_connection(&self.pool)?;

        //  Get the slot of the highest entry in the `block_rewards` table.
        let highest_filled_slot_opt = if self.config.block_rewards {
            database::get_highest_block_rewards(&mut conn)?.map(|reward| reward.slot)
        } else {
            return Err(Error::NotEnabled("block_rewards".to_string()));
        };

        let mut start_slot = if let Some(highest_filled_slot) = highest_filled_slot_opt {
            highest_filled_slot.as_slot() + 1
        } else {
            // No entries in the `block_rewards` table. Use `beacon_blocks` instead.
            if let Some(lowest_beacon_block) =
                database::get_lowest_beacon_block(&mut conn)?.map(|block| block.slot)
            {
                lowest_beacon_block.as_slot()
            } else {
                // There are no blocks in the database, do not fill the `block_rewards` table.
                warn!("Refusing to fill block rewards as there are no blocks in the database");
                return Ok(());
            }
        };

        // The `block_rewards` API cannot accept `start_slot == 0`.
        if start_slot == 0 {
            start_slot += 1;
        }

        if let Some(highest_beacon_block) =
            database::get_highest_beacon_block(&mut conn)?.map(|block| block.slot)
        {
            let mut end_slot = highest_beacon_block.as_slot();

            if start_slot > end_slot {
                debug!("Block rewards are up to date with the head of the database");
                return Ok(());
            }

            // Ensure the size of the request does not exceed the maximum allowed value.
            if start_slot < end_slot.saturating_sub(MAX_SIZE_SINGLE_REQUEST_BLOCK_REWARDS) {
                end_slot = start_slot + MAX_SIZE_SINGLE_REQUEST_BLOCK_REWARDS
            }

            let rewards = get_block_rewards(&self.bn, start_slot, end_slot).await?;
            database::insert_batch_block_rewards(&mut conn, rewards)?;
        } else {
            // There are no blocks in the `beacon_blocks` database, but there are entries in the
            // `block_rewards` table. This is a critical failure. It usually means someone has
            // manually tampered with the database tables and should not occur during normal
            // operation.
            error!("Database is corrupted. Please re-sync the database");
            return Err(Error::Database(DbError::DatabaseCorrupted));
        }

        Ok(())
    }

    /// Backfill the `block_rewards` tables starting from the entry with the
    /// lowest slot.
    ///
    /// It constructs a request to the `get_block_rewards` API with:
    /// `start_slot` -> lowest_beacon_block
    /// `end_slot` -> lowest filled `block_rewards` - 1 (or highest beacon block)
    ///
    /// Request range will not exceed `MAX_SIZE_SINGLE_REQUEST_BLOCK_REWARDS`.
    pub async fn backfill_block_rewards(&mut self) -> Result<(), Error> {
        let mut conn = database::get_connection(&self.pool)?;
        let max_block_reward_backfill = self.config.max_backfill_size_epochs * self.slots_per_epoch;

        // Get the slot of the lowest entry in the `block_rewards` table.
        let lowest_filled_slot_opt = if self.config.block_rewards {
            database::get_lowest_block_rewards(&mut conn)?.map(|reward| reward.slot)
        } else {
            return Err(Error::NotEnabled("block_rewards".to_string()));
        };

        let end_slot = if let Some(lowest_filled_slot) = lowest_filled_slot_opt {
            lowest_filled_slot.as_slot().saturating_sub(1_u64)
        } else {
            // No entries in the `block_rewards` table. Use `beacon_blocks` instead.
            if let Some(highest_beacon_block) =
                database::get_highest_beacon_block(&mut conn)?.map(|block| block.slot)
            {
                highest_beacon_block.as_slot()
            } else {
                // There are no blocks in the database, do not backfill the `block_rewards` table.
                warn!("Refusing to backfill block rewards as there are no blocks in the database");
                return Ok(());
            }
        };

        if end_slot <= 1 {
            debug!("Block rewards backfill is complete");
            return Ok(());
        }

        if let Some(lowest_block_slot) = database::get_lowest_beacon_block(&mut conn)? {
            let mut start_slot = lowest_block_slot.slot.as_slot();

            if start_slot >= end_slot {
                debug!("Block rewards are up to date with the base of the database");
                return Ok(());
            }

            // Ensure that the request range does not exceed `max_block_reward_backfill` or
            // `MAX_SIZE_SINGLE_REQUEST_BLOCK_REWARDS`.
            if start_slot < end_slot.saturating_sub(max_block_reward_backfill) {
                start_slot = end_slot.saturating_sub(max_block_reward_backfill)
            }

            if start_slot < end_slot.saturating_sub(MAX_SIZE_SINGLE_REQUEST_BLOCK_REWARDS) {
                start_slot = end_slot.saturating_sub(MAX_SIZE_SINGLE_REQUEST_BLOCK_REWARDS)
            }

            // The `block_rewards` API cannot accept `start_slot == 0`.
            if start_slot == 0 {
                start_slot += 1
            }

            let rewards = get_block_rewards(&self.bn, start_slot, end_slot).await?;

            if self.config.block_rewards {
                database::insert_batch_block_rewards(&mut conn, rewards)?;
            }
        } else {
            // There are no blocks in the `beacon_blocks` database, but there are entries in the
            // `block_rewards` table. This is a critical failure. It usually means someone has
            // manually tampered with the database tables and should not occur during normal
            // operation.
            error!("Database is corrupted. Please re-sync the database");
            return Err(Error::Database(DbError::DatabaseCorrupted));
        }

        Ok(())
    }
}
