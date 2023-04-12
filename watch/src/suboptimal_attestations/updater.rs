use crate::database::{self, Error as DbError};
use crate::updater::{Error, UpdateHandler};

use crate::suboptimal_attestations::get_attestation_performances;

use eth2::types::EthSpec;
use log::{debug, error, warn};

const MAX_SIZE_SINGLE_REQUEST_ATTESTATIONS: u64 = 50;

impl<T: EthSpec> UpdateHandler<T> {
    /// Forward fills the `suboptimal_attestations` table starting from the entry with the highest
    /// slot.
    ///
    /// It construts a request to the `attestation_performance` API endpoint with:
    /// `start_epoch` -> highest completely filled epoch + 1 (or epoch of lowest canonical slot)
    /// `end_epoch` -> epoch of highest canonical slot
    ///
    /// It will resync the latest epoch if it is not fully filled but will not overwrite existing
    /// values unless there is a re-org.
    /// That is, `if highest_filled_slot % slots_per_epoch != 31`.
    ///
    /// In the event the most recent epoch has no suboptimal attestations, it will attempt to
    /// resync that epoch. The odds of this occuring on mainnet are vanishingly small so it is not
    /// accounted for.
    ///
    /// Request range will not exceed `MAX_SIZE_SINGLE_REQUEST_ATTESTATIONS`.
    pub async fn fill_suboptimal_attestations(&mut self) -> Result<(), Error> {
        let mut conn = database::get_connection(&self.pool)?;

        let highest_filled_slot_opt = if self.config.attestations {
            database::get_highest_attestation(&mut conn)?
                .map(|attestation| attestation.epoch_start_slot.as_slot())
        } else {
            return Err(Error::NotEnabled("attestations".to_string()));
        };

        let start_epoch = if let Some(highest_filled_slot) = highest_filled_slot_opt {
            if highest_filled_slot % self.slots_per_epoch == self.slots_per_epoch.saturating_sub(1)
            {
                // The whole epoch is filled so we can begin syncing the next one.
                highest_filled_slot.epoch(self.slots_per_epoch) + 1
            } else {
                // The epoch is only partially synced. Try to sync it fully.
                highest_filled_slot.epoch(self.slots_per_epoch)
            }
        } else {
            // No rows present in the `suboptimal_attestations` table. Use `canonical_slots`
            // instead.
            if let Some(lowest_canonical_slot) = database::get_lowest_canonical_slot(&mut conn)? {
                lowest_canonical_slot
                    .slot
                    .as_slot()
                    .epoch(self.slots_per_epoch)
            } else {
                // There are no slots in the database, do not fill the `suboptimal_attestations`
                // table.
                warn!("Refusing to fill the `suboptimal_attestations` table as there are no slots in the database");
                return Ok(());
            }
        };

        if let Some(highest_canonical_slot) =
            database::get_highest_canonical_slot(&mut conn)?.map(|slot| slot.slot.as_slot())
        {
            let mut end_epoch = highest_canonical_slot.epoch(self.slots_per_epoch);

            // The `lighthouse/analysis/attestation_performance` endpoint can only retrieve attestations
            // which are more than 1 epoch old.
            // We assume that `highest_canonical_slot` is near the head of the chain.
            end_epoch = end_epoch.saturating_sub(2_u64);

            // If end_epoch == 0 then the chain just started so we need to wait until
            // `current_epoch >= 2`.
            if end_epoch == 0 {
                debug!("Chain just begun, refusing to sync attestations");
                return Ok(());
            }

            if start_epoch > end_epoch {
                debug!("Attestations are up to date with the head of the database");
                return Ok(());
            }

            // Ensure the size of the request does not exceed the maximum allowed value.
            if start_epoch < end_epoch.saturating_sub(MAX_SIZE_SINGLE_REQUEST_ATTESTATIONS) {
                end_epoch = start_epoch + MAX_SIZE_SINGLE_REQUEST_ATTESTATIONS
            }

            if let Some(lowest_canonical_slot) =
                database::get_lowest_canonical_slot(&mut conn)?.map(|slot| slot.slot.as_slot())
            {
                let mut attestations = get_attestation_performances(
                    &self.bn,
                    start_epoch,
                    end_epoch,
                    self.slots_per_epoch,
                )
                .await?;

                // Only insert attestations with corresponding `canonical_slot`s.
                attestations.retain(|attestation| {
                    attestation.epoch_start_slot.as_slot() >= lowest_canonical_slot
                        && attestation.epoch_start_slot.as_slot() <= highest_canonical_slot
                });
                database::insert_batch_suboptimal_attestations(&mut conn, attestations)?;
            } else {
                return Err(Error::Database(DbError::Other(
                    "Database did not return a lowest canonical slot when one exists".to_string(),
                )));
            }
        } else {
            // There are no slots in the `canonical_slots` table, but there are entries in the
            // `suboptimal_attestations` table. This is a critical failure. It usually means
            // someone has manually tampered with the database tables and should not occur during
            // normal operation.
            error!("Database is corrupted. Please re-sync the database");
            return Err(Error::Database(DbError::DatabaseCorrupted));
        }

        Ok(())
    }

    /// Backfill the `suboptimal_attestations` table starting from the entry with the lowest slot.
    ///
    /// It constructs a request to the `attestation_performance` API endpoint with:
    /// `start_epoch` -> epoch of the lowest `canonical_slot`.
    /// `end_epoch` -> epoch of the lowest filled `suboptimal_attestation` - 1 (or epoch of highest
    /// canonical slot)
    ///
    /// It will resync the lowest epoch if it is not fully filled.
    /// That is, `if lowest_filled_slot % slots_per_epoch != 0`
    ///
    /// In the event there are no suboptimal attestations present in the lowest epoch, it will attempt to
    /// resync the epoch. The odds of this occuring on mainnet are vanishingly small so it is not
    /// accounted for.
    ///
    /// Request range will not exceed `MAX_SIZE_SINGLE_REQUEST_ATTESTATIONS`.
    pub async fn backfill_suboptimal_attestations(&mut self) -> Result<(), Error> {
        let mut conn = database::get_connection(&self.pool)?;
        let max_attestation_backfill = self.config.max_backfill_size_epochs;

        // Get the slot of the lowest entry in the `suboptimal_attestations` table.
        let lowest_filled_slot_opt = if self.config.attestations {
            database::get_lowest_attestation(&mut conn)?
                .map(|attestation| attestation.epoch_start_slot.as_slot())
        } else {
            return Err(Error::NotEnabled("attestations".to_string()));
        };

        let end_epoch = if let Some(lowest_filled_slot) = lowest_filled_slot_opt {
            if lowest_filled_slot % self.slots_per_epoch == 0 {
                lowest_filled_slot
                    .epoch(self.slots_per_epoch)
                    .saturating_sub(1_u64)
            } else {
                // The epoch is only partially synced. Try to sync it fully.
                lowest_filled_slot.epoch(self.slots_per_epoch)
            }
        } else {
            // No entries in the `suboptimal_attestations` table. Use `canonical_slots` instead.
            if let Some(highest_canonical_slot) =
                database::get_highest_canonical_slot(&mut conn)?.map(|slot| slot.slot.as_slot())
            {
                // Subtract 2 since `end_epoch` must be less than the current epoch - 1.
                // We assume that `highest_canonical_slot` is near the head of the chain.
                highest_canonical_slot
                    .epoch(self.slots_per_epoch)
                    .saturating_sub(2_u64)
            } else {
                // There are no slots in the database, do not backfill the
                // `suboptimal_attestations` table.
                warn!("Refusing to backfill attestations as there are no slots in the database");
                return Ok(());
            }
        };

        if end_epoch == 0 {
            debug!("Attestations backfill is complete");
            return Ok(());
        }

        if let Some(lowest_canonical_slot) =
            database::get_lowest_canonical_slot(&mut conn)?.map(|slot| slot.slot.as_slot())
        {
            let mut start_epoch = lowest_canonical_slot.epoch(self.slots_per_epoch);

            if start_epoch > end_epoch {
                debug!("Attestations are up to date with the base of the database");
                return Ok(());
            }

            // Ensure the request range does not exceed `max_attestation_backfill` or
            // `MAX_SIZE_SINGLE_REQUEST_ATTESTATIONS`.
            if start_epoch < end_epoch.saturating_sub(max_attestation_backfill) {
                start_epoch = end_epoch.saturating_sub(max_attestation_backfill)
            }
            if start_epoch < end_epoch.saturating_sub(MAX_SIZE_SINGLE_REQUEST_ATTESTATIONS) {
                start_epoch = end_epoch.saturating_sub(MAX_SIZE_SINGLE_REQUEST_ATTESTATIONS)
            }

            if let Some(highest_canonical_slot) =
                database::get_highest_canonical_slot(&mut conn)?.map(|slot| slot.slot.as_slot())
            {
                let mut attestations = get_attestation_performances(
                    &self.bn,
                    start_epoch,
                    end_epoch,
                    self.slots_per_epoch,
                )
                .await?;

                // Only insert `suboptimal_attestations` with corresponding `canonical_slots`.
                attestations.retain(|attestation| {
                    attestation.epoch_start_slot.as_slot() >= lowest_canonical_slot
                        && attestation.epoch_start_slot.as_slot() <= highest_canonical_slot
                });

                database::insert_batch_suboptimal_attestations(&mut conn, attestations)?;
            } else {
                return Err(Error::Database(DbError::Other(
                    "Database did not return a lowest slot when one exists".to_string(),
                )));
            }
        } else {
            // There are no slots in the `canonical_slot` table, but there are entries in the
            // `suboptimal_attestations` table. This is a critical failure. It usually means
            // someone has manually tampered with the database tables and should not occur during
            // normal operation.
            error!("Database is corrupted. Please re-sync the database");
            return Err(Error::Database(DbError::DatabaseCorrupted));
        }

        Ok(())
    }
}
