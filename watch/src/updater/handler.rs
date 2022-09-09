use crate::blockprint::WatchBlockprintClient;
use crate::config::Config as FullConfig;
use crate::database::{self, Error as DbError, PgPool, WatchCanonicalSlot, WatchHash, WatchSlot};
use crate::updater::{Config, Error};
use beacon_node::beacon_chain::BeaconChainError;
use eth2::{
    types::{BlockId, SyncingData},
    BeaconNodeHttpClient, SensitiveUrl, Timeouts,
};
use log::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::time::{Duration, Instant};
use types::{BeaconBlockHeader, Epoch, Hash256, Slot};

use crate::updater::{
    get_attestation_performances, get_block_packing, get_block_rewards_and_proposer_info,
    get_header, get_validators,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_EXPECTED_REORG_LENGTH: u64 = 32;
const MAX_SIZE_SINGLE_REQUEST_ATTESTATIONS: u64 = 50;
const MAX_SIZE_SINGLE_REQUEST_BLOCK_REWARDS: u64 = 1600;
const MAX_SIZE_SINGLE_REQUEST_BLOCK_PACKING: u64 = 50;

/// Ensure the existing database is valid for this run and returns the slots_per_epoch value
/// to use.
pub async fn ensure_valid_database(
    bn: BeaconNodeHttpClient,
    pool: &mut PgPool,
) -> Result<u64, Error> {
    let mut conn = database::get_connection(pool)?;

    let spec = bn.get_config_spec::<HashMap<String, String>>().await?.data;

    let bn_config_name = spec
        .get("CONFIG_NAME")
        .ok_or_else(|| {
            Error::BeaconNodeNotCompatible("No field CONFIG_NAME on beacon node spec".to_string())
        })?
        .clone();

    let bn_slots_per_epoch: u64 = spec
        .get("SLOTS_PER_EPOCH")
        .ok_or_else(|| {
            Error::BeaconNodeNotCompatible(
                "No field SLOTS_PER_EPOCH on beacon node spec".to_string(),
            )
        })?
        .parse()
        .map_err(|e| {
            Error::BeaconNodeNotCompatible(format!("Unable to parse field SLOTS_PER_EPOCH: {e}"))
        })?;

    if let Some((db_config_name, db_slots_per_epoch)) = database::get_active_config(&mut conn)? {
        if db_config_name != bn_config_name || db_slots_per_epoch != bn_slots_per_epoch as i32 {
            Err(Error::InvalidConfig(
                "The config stored in the database does not match the beacon node.".to_string(),
            ))
        } else {
            // Configs match.
            Ok(bn_slots_per_epoch)
        }
    } else {
        // No config exists in the DB.
        database::insert_active_config(&mut conn, bn_config_name, bn_slots_per_epoch as i32)?;
        Ok(bn_slots_per_epoch)
    }
}

pub struct UpdateHandler {
    pool: PgPool,
    bn: BeaconNodeHttpClient,
    blockprint: Option<WatchBlockprintClient>,
    config: Config,
    slots_per_epoch: u64,
}

impl UpdateHandler {
    pub async fn new(config: FullConfig) -> Result<UpdateHandler, Error> {
        let beacon_node_url =
            SensitiveUrl::parse(&config.updater.beacon_node_url).map_err(Error::SensitiveUrl)?;
        let bn = BeaconNodeHttpClient::new(beacon_node_url, Timeouts::set_all(DEFAULT_TIMEOUT));

        let blockprint = if config.blockprint.enabled {
            if let Some(server) = config.blockprint.url {
                let blockprint_url = SensitiveUrl::parse(&server).map_err(Error::SensitiveUrl)?;
                Some(WatchBlockprintClient {
                    client: reqwest::Client::new(),
                    server: blockprint_url,
                    username: config.blockprint.username,
                    password: config.blockprint.password,
                })
            } else {
                return Err(Error::NotEnabled(
                    "blockprint was enabled but url was not set".to_string(),
                ));
            }
        } else {
            None
        };

        let mut pool = database::build_connection_pool(&config.database)?;

        let slots_per_epoch = ensure_valid_database(bn.clone(), &mut pool).await?;

        Ok(Self {
            pool,
            bn,
            blockprint,
            config: config.updater,
            slots_per_epoch,
        })
    }

    /// Gets the syncing status of the connected beacon node.
    pub async fn get_bn_syncing_status(&mut self) -> Result<SyncingData, Error> {
        Ok(self.bn.get_node_syncing().await?.data)
    }

    /// Gets a list of block roots from the database which do not yet contain a corresponding
    /// entry in the `beacon_blocks` table and inserts them.
    pub async fn update_unknown_blocks(&mut self) -> Result<(), Error> {
        let mut conn = database::get_connection(&self.pool)?;
        let roots = database::get_unknown_canonical_blocks(&mut conn)?;
        for root in roots {
            if let Some(header) = get_header(&self.bn, BlockId::Root(root.as_hash())).await? {
                database::insert_beacon_block_from_header(&mut conn, &header, root)?;
            }
        }

        Ok(())
    }

    /// Performs a head update with the following steps:
    /// 1. Pull the latest header from the beacon node and the latest canonical slot from the
    /// database.
    /// 2. Loop back through the beacon node and database to find the first matching slot -> root
    /// pair.
    /// 3. Go back `MAX_EXPECTED_REORG_LENGTH` slots through the database ensuring it is
    /// consistent with the beacon node. If a re-org occurs beyond this range, we cannot recover.
    /// 4. Remove any invalid slots from the database.
    /// 5. Sync all blocks between the first valid block of the database and the head of the beacon
    /// chain.
    ///
    /// In the event there are no slots present in the database, it will sync from the head block
    /// block back to the first slot of the epoch.
    /// This will ensure backfills are always done in full epochs (which helps keep certain syncing
    /// tasks efficient).
    pub async fn perform_head_update(&mut self) -> Result<(), Error> {
        let mut conn = database::get_connection(&self.pool)?;
        // Load the head from the beacon node.
        let bn_header = get_header(&self.bn, BlockId::Head)
            .await?
            .ok_or(Error::UnableToGetRemoteHead)?;
        let header_root = bn_header.canonical_root();

        if let Some(latest_matching_canonical_slot) =
            self.get_first_matching_block(bn_header.clone()).await?
        {
            // Check for reorgs.
            let latest_db_slot = self.check_for_reorg(latest_matching_canonical_slot).await?;

            // Remove all slots above `latest_db_slot` from the database.
            let result = database::delete_canonical_slots_above(
                &mut conn,
                WatchSlot::from_slot(latest_db_slot),
            )?;
            info!("{result} old records removed during head update");

            if result > 0 {
                // If slots were removed, we need to resync the suboptimal_attestations table for
                // the epoch since they will have changed and cannot be fixed by a simple update.
                let epoch = latest_db_slot
                    .epoch(self.slots_per_epoch)
                    .saturating_sub(1_u64);
                debug!("Preparing to resync attestations above epoch {epoch}");
                database::delete_suboptimal_attestations_above(
                    &mut conn,
                    WatchSlot::from_slot(epoch.start_slot(self.slots_per_epoch)),
                )?;
            }

            // Since we are syncing backwards, `start_slot > `end_slot`.
            let start_slot = bn_header.slot;
            let end_slot = latest_db_slot + 1;
            self.reverse_fill_canonical_slots(bn_header, header_root, false, start_slot, end_slot)
                .await?;
            info!("Reverse sync begun at slot {start_slot} and stopped at slot {end_slot}");

            // Attempt to sync new blocks with blockprint.
            self.sync_blockprint_until(start_slot).await?;
        } else {
            // There are no matching parent blocks. Sync from the head block back until the first
            // block of the epoch.
            let start_slot = bn_header.slot;
            let end_slot = start_slot.saturating_sub(start_slot % self.slots_per_epoch);
            self.reverse_fill_canonical_slots(bn_header, header_root, false, start_slot, end_slot)
                .await?;
            info!("Reverse sync begun at slot {start_slot} and stopped at slot {end_slot}");
        }

        Ok(())
    }

    /// Attempt to find a row in the `canonical_slots` table which matches the `canonical_root` of
    /// the block header as reported by the beacon node.
    ///
    /// Any blocks above this value are not canonical according to the beacon node.
    ///
    /// Note: In the event that there are skip slots above the slot returned by the function,
    /// they will not be returned, so may be pruned or re-synced by other code despite being
    /// canonical.
    pub async fn get_first_matching_block(
        &mut self,
        mut bn_header: BeaconBlockHeader,
    ) -> Result<Option<WatchCanonicalSlot>, Error> {
        let mut conn = database::get_connection(&self.pool)?;

        // Load latest non-skipped canonical slot from database.
        if let Some(db_canonical_slot) =
            database::get_highest_non_skipped_canonical_slot(&mut conn)?
        {
            // Check if the header or parent root matches the entry in the database.
            if bn_header.parent_root == db_canonical_slot.root.as_hash()
                || bn_header.canonical_root() == db_canonical_slot.root.as_hash()
            {
                Ok(Some(db_canonical_slot))
            } else {
                // Header is not the child of the highest entry in the database.
                // From here we need to iterate backwards through the database until we find
                // a slot -> root pair that matches the beacon node.
                loop {
                    // Store working `parent_root`.
                    let parent_root = bn_header.parent_root;

                    // Try the next header.
                    let next_header = get_header(&self.bn, BlockId::Root(parent_root)).await?;
                    if let Some(header) = next_header {
                        bn_header = header.clone();
                        if let Some(db_canonical_slot) = database::get_canonical_slot_by_root(
                            &mut conn,
                            WatchHash::from_hash(header.parent_root),
                        )? {
                            // Check if the entry in the database matches the parent of
                            // the header.
                            if header.parent_root == db_canonical_slot.root.as_hash() {
                                return Ok(Some(db_canonical_slot));
                            } else {
                                // Move on to the next header.
                                continue;
                            }
                        } else {
                            // Database does not have the referenced root. Try the next header.
                            continue;
                        }
                    } else {
                        // If we get this error it means that the `parent_root` of the header
                        // did not reference a canonical block.
                        return Err(Error::BeaconChain(BeaconChainError::MissingBeaconBlock(
                            parent_root,
                        )));
                    }
                }
            }
        } else {
            // There are no non-skipped blocks present in the database.
            Ok(None)
        }
    }

    /// Given the latest slot in the database which matches a root in the beacon node,
    /// traverse back through the database for `MAX_EXPECTED_REORG_LENGTH` slots to ensure the tip
    /// of the database is consistent with the beacon node (in the case that reorgs have occured).
    ///
    /// Returns the slot before the oldest canonical_slot which has an invalid child.
    pub async fn check_for_reorg(
        &mut self,
        latest_canonical_slot: WatchCanonicalSlot,
    ) -> Result<Slot, Error> {
        let mut conn = database::get_connection(&self.pool)?;

        let end_slot = latest_canonical_slot.slot.as_u64();
        let start_slot = end_slot.saturating_sub(MAX_EXPECTED_REORG_LENGTH);

        for i in start_slot..end_slot {
            let slot = Slot::new(i);
            let db_canonical_slot_opt =
                database::get_canonical_slot(&mut conn, WatchSlot::from_slot(slot))?;
            if let Some(db_canonical_slot) = db_canonical_slot_opt {
                let header_opt = get_header(&self.bn, BlockId::Slot(slot)).await?;
                if let Some(header) = header_opt {
                    if header.canonical_root() == db_canonical_slot.root.as_hash() {
                        // The roots match (or are both skip slots).
                        continue;
                    } else {
                        // The block roots do not match. We need to re-sync from here.
                        warn!("Block {slot} does not match the beacon node. Resyncing");
                        return Ok(slot.saturating_sub(1_u64));
                    }
                } else if !db_canonical_slot.skipped {
                    // The block exists in the database, but does not exist on the beacon node.
                    // We need to re-sync from here.
                    warn!("Block {slot} does not exist on the beacon node. Resyncing");
                    return Ok(slot.saturating_sub(1_u64));
                }
            } else {
                // This slot does not exist in the database.
                let lowest_slot = database::get_lowest_canonical_slot(&mut conn)?
                    .map(|canonical_slot| canonical_slot.slot.as_slot());
                if lowest_slot > Some(slot) {
                    // The database has not back-filled this slot yet, so skip it.
                    continue;
                } else {
                    // The database does not contain this block, but has back-filled past it.
                    // We need to resync from here.
                    warn!("Slot {slot} missing from database. Resyncing");
                    return Ok(slot.saturating_sub(1_u64));
                }
            }
        }

        // The database is consistent with the beacon node, so return the head of the database.
        Ok(latest_canonical_slot.slot.as_slot())
    }

    /// Fills the canonical slots table beginning from `start_slot` and ending at `end_slot`.
    /// It fills in reverse order, that is, `start_slot` is higher than `end_slot`.
    ///
    /// Skip slots set `root` to the root of the previous non-skipped slot and also sets
    /// `skipped == true`.
    ///
    /// Since it uses `insert_canonical_slot` to interact with the database, it WILL NOT overwrite
    /// existing rows. This means that any part of the chain within `end_slot..=start_slot` that
    /// needs to be resynced, must first be deleted from the database.
    pub async fn reverse_fill_canonical_slots(
        &mut self,
        mut header: BeaconBlockHeader,
        mut header_root: Hash256,
        mut skipped: bool,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<usize, Error> {
        let mut count = 0;

        let mut conn = database::get_connection(&self.pool)?;

        // Iterate, descending from `start_slot` (higher) to `end_slot` (lower).
        for slot in (end_slot.as_u64()..=start_slot.as_u64()).rev() {
            // Insert header.
            database::insert_canonical_slot(
                &mut conn,
                WatchCanonicalSlot {
                    slot: WatchSlot::new(slot),
                    root: WatchHash::from_hash(header_root),
                    skipped,
                    beacon_block: None,
                },
            )?;
            count += 1;

            // Load the next header:
            // We must use BlockId::Slot since we want to include skip slots.
            header = if let Some(new_header) = get_header(
                &self.bn,
                BlockId::Slot(Slot::new(slot.saturating_sub(1_u64))),
            )
            .await?
            {
                header_root = new_header.canonical_root();
                skipped = false;
                new_header
            } else {
                if header.slot == 0 {
                    info!("Reverse fill exhausted at slot 0");
                    break;
                }
                // Slot was skipped, so use the parent_root (most recent non-skipped block).
                skipped = true;
                header_root = header.parent_root;
                header
            };
        }

        Ok(count)
    }

    /// Backfills the `canonical_slots` table starting from the lowest non-skipped slot and
    /// stopping after `max_backfill_size_epochs` epochs.
    pub async fn backfill_canonical_slots(&mut self) -> Result<(), Error> {
        let mut conn = database::get_connection(&self.pool)?;
        let backfill_stop_slot = self.config.backfill_stop_epoch * self.slots_per_epoch;
        // Check to see if we have finished backfilling.
        if let Some(lowest_slot) = database::get_lowest_canonical_slot(&mut conn)? {
            if lowest_slot.slot.as_slot() == backfill_stop_slot {
                debug!("Backfill sync complete, all slots filled");
                return Ok(());
            }
        }

        let backfill_slot_count = self.config.max_backfill_size_epochs * self.slots_per_epoch;

        if let Some(lowest_non_skipped_canonical_slot) =
            database::get_lowest_non_skipped_canonical_slot(&mut conn)?
        {
            // Set `start_slot` equal to the lowest non-skipped slot in the database.
            // While this will attempt to resync some parts of the bottom of the chain, it reduces
            // complexity when dealing with skip slots.
            let start_slot = lowest_non_skipped_canonical_slot.slot.as_slot();
            let mut end_slot = lowest_non_skipped_canonical_slot
                .slot
                .as_slot()
                .saturating_sub(backfill_slot_count);

            // Ensure end_slot doesn't go below `backfill_stop_epoch`
            if end_slot <= backfill_stop_slot {
                end_slot = Slot::new(backfill_stop_slot);
            }

            let header_opt = get_header(&self.bn, BlockId::Slot(start_slot)).await?;

            if let Some(header) = header_opt {
                let header_root = header.canonical_root();
                let count = self
                    .reverse_fill_canonical_slots(header, header_root, false, start_slot, end_slot)
                    .await?;

                info!("Backfill completed to slot: {end_slot}, records added: {count}");
            } else {
                // The lowest slot of the database is inconsistent with the beacon node.
                // Currently we have no way to recover from this. The entire database will need to
                // be re-synced.
                error!(
                    "Database is inconsistent with the beacon node. \
                    Please ensure your beacon node is set to the right network, \
                    otherwise you may need to resync"
                );
            }
        } else {
            // There are no blocks in the database. Forward sync needs to happen first.
            info!("Backfill was not performed since there are no blocks in the database");
            return Ok(());
        };

        Ok(())
    }

    // Attempt to update the validator set.
    // This downloads the latest validator set from the beacon node, and pulls the known validator
    // set from the database.
    // We then take any new or updated validators and insert them into the database (overwriting
    // exiting validators).
    //
    // In the event there are no validators in the database, it will initialize the validator set.
    pub async fn update_validator_set(&mut self) -> Result<(), Error> {
        let mut conn = database::get_connection(&self.pool)?;

        let current_validators = database::get_all_validators(&mut conn)?;

        if !current_validators.is_empty() {
            let old_validators = HashSet::from_iter(current_validators);

            // Pull the new validator set from the beacon node.
            let new_validators = get_validators(&self.bn).await?;

            // The difference should only contain validators that contain either a new `exit_epoch` (implying an
            // exit) or a new `index` (implying a validator activation).
            let val_diff = new_validators.difference(&old_validators);

            for diff in val_diff {
                database::insert_validator(&mut conn, diff.clone())?;
            }
        } else {
            info!("No validators present in database. Initializing the validator set");
            self.initialize_validator_set().await?;
        }

        Ok(())
    }

    // Initialize the validator set by downloading it from the beacon node, inserting blockprint
    // data (if required) and writing it to the database.
    pub async fn initialize_validator_set(&mut self) -> Result<(), Error> {
        let mut conn = database::get_connection(&self.pool)?;

        // Pull all validators from the beacon node.
        let mut validators = Vec::from_iter(get_validators(&self.bn).await?);

        let highest_validator = validators.len() as i32 + 1;

        if let Some(blockprint) = &self.blockprint {
            debug!("Syncing from blockprint");
            // Ensure blockprint is synced.
            let _ = blockprint.ensure_synced().await?;

            let timer = Instant::now();
            let blockprint_data = blockprint
                .blockprint_all_validators(highest_validator)
                .await?;

            for val in &mut validators {
                val.client = blockprint_data.get(&val.index).cloned();
            }

            // Store the highest slot as the current blockprint checkpoint.
            if let Some(highest_slot) = database::get_highest_canonical_slot(&mut conn)? {
                database::update_blockprint_checkpoint(&mut conn, highest_slot.slot)?;
            } else {
                return Err(Error::Database(DbError::Other(
                    "Updater should always update blocks before initializing the validator set"
                        .to_string(),
                )));
            }

            let elapsed = timer.elapsed();
            debug!("Syncing from blockprint complete, time taken: {elapsed:?}");
        }

        database::insert_batch_validators(&mut conn, validators)?;

        Ok(())
    }

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
            if start_epoch > end_epoch + MAX_SIZE_SINGLE_REQUEST_ATTESTATIONS {
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

    /// Forward fills the `block_rewards`/`proposer_info` tables starting from the entry with the
    /// highest slot.
    ///
    /// It constructs a request to the `get_block_rewards` API with:
    /// `start_slot` -> highest filled `block_rewards` + 1 (or lowest beacon block)
    /// `end_slot` -> highest beacon block
    ///
    /// Request range will not exceed `MAX_SIZE_SINGLE_REQUEST_BLOCK_REWARDS`.
    pub async fn fill_block_rewards_and_proposer_info(&mut self) -> Result<(), Error> {
        let mut conn = database::get_connection(&self.pool)?;

        //  Get the slot of the highest entry in the `block_rewards`/`proposer_info` table.
        let highest_filled_slot_opt = if self.config.block_rewards {
            database::get_highest_block_rewards(&mut conn)?.map(|reward| reward.slot)
        } else if self.config.proposer_info {
            database::get_highest_proposer_info(&mut conn)?.map(|info| info.slot)
        } else {
            return Err(Error::NotEnabled("block_rewards/proposer_info".to_string()));
        };

        let mut start_slot = if let Some(highest_filled_slot) = highest_filled_slot_opt {
            highest_filled_slot.as_slot() + 1
        } else {
            // No entries in the `block_rewards` or `proposer_info` tables. Use `beacon_blocks`
            // instead.
            if let Some(lowest_beacon_block) =
                database::get_lowest_beacon_block(&mut conn)?.map(|block| block.slot)
            {
                lowest_beacon_block.as_slot()
            } else {
                // There are no blocks in the database, do not fill the `block_rewards` or
                // `proposer_info` tables.
                warn!("Refusing to fill block rewards/proposer info as there are no blocks in the database");
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
                debug!("Block rewards/proposer info are up to date with the head of the database");
                return Ok(());
            }

            // Ensure the size of the request does not exceed the maximum allowed value.
            if start_slot > end_slot + MAX_SIZE_SINGLE_REQUEST_BLOCK_REWARDS {
                end_slot = start_slot + MAX_SIZE_SINGLE_REQUEST_BLOCK_REWARDS
            }

            let (rewards, proposer_info) =
                get_block_rewards_and_proposer_info(&self.bn, start_slot, end_slot).await?;

            if self.config.block_rewards {
                database::insert_batch_block_rewards(&mut conn, rewards)?;
            }
            if self.config.proposer_info {
                database::insert_batch_proposer_info(&mut conn, proposer_info)?;
            }
        } else {
            // There are no blocks in the `beacon_blocks` database, but there are entries in either
            // `block_rewards`/`proposer_info` tables. This is a critical failure. It usually means
            // someone has manually tampered with the database tables and should not occur during
            // normal operation.
            error!("Database is corrupted. Please re-sync the database");
            return Err(Error::Database(DbError::DatabaseCorrupted));
        }

        Ok(())
    }

    /// Backfill the `block_rewards` and `proposer_info` tables starting from the entry with the
    /// lowest slot.
    ///
    /// It constructs a request to the `get_block_rewards` API with:
    /// `start_slot` -> lowest_beacon_block
    /// `end_slot` -> lowest filled `block_rewards` - 1 (or highest beacon block)
    ///
    /// Request range will not exceed `MAX_SIZE_SINGLE_REQUEST_BLOCK_REWARDS`.
    pub async fn backfill_block_rewards_and_proposer_info(&mut self) -> Result<(), Error> {
        let mut conn = database::get_connection(&self.pool)?;
        let max_block_reward_backfill = self.config.max_backfill_size_epochs * self.slots_per_epoch;

        // Get the slot of the lowest entry in the `block_rewards`/`proposer_info` table.
        let lowest_filled_slot_opt = if self.config.block_rewards {
            database::get_lowest_block_rewards(&mut conn)?.map(|reward| reward.slot)
        } else if self.config.proposer_info {
            database::get_lowest_proposer_info(&mut conn)?.map(|info| info.slot)
        } else {
            return Err(Error::NotEnabled(
                "block_rewards or proposer_info".to_string(),
            ));
        };

        let end_slot = if let Some(lowest_filled_slot) = lowest_filled_slot_opt {
            lowest_filled_slot.as_slot().saturating_sub(1_u64)
        } else {
            // No entries in the `block_rewards` or `proposer_info` tables. Use `beacon_blocks`
            // instead.
            if let Some(highest_beacon_block) =
                database::get_highest_beacon_block(&mut conn)?.map(|block| block.slot)
            {
                highest_beacon_block.as_slot()
            } else {
                // There are no blocks in the database, do not backfill the `block_rewards` or
                // `proposer_info` tables.
                warn!("Refusing to backfill block rewards/proposer info as there are no blocks in the database");
                return Ok(());
            }
        };

        if end_slot <= 1 {
            debug!("Block rewards/proposer info backfill is complete");
            return Ok(());
        }

        if let Some(lowest_block_slot) = database::get_lowest_beacon_block(&mut conn)? {
            let mut start_slot = lowest_block_slot.slot.as_slot();

            if start_slot >= end_slot {
                debug!("Block rewards/proposer info are up to date with the base of the database");
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

            let (rewards, proposer_info) =
                get_block_rewards_and_proposer_info(&self.bn, start_slot, end_slot).await?;

            if self.config.block_rewards {
                database::insert_batch_block_rewards(&mut conn, rewards)?;
            }
            if self.config.proposer_info {
                database::insert_batch_proposer_info(&mut conn, proposer_info)?;
            }
        } else {
            // There are no blocks in the `beacon_blocks` database, but there are entries in either
            // `block_rewards`/`proposer_info` tables. This is a critical failure. It usually means
            // someone has manually tampered with the database tables and should not occur during
            // normal operation.
            error!("Database is corrupted. Please re-sync the database");
            return Err(Error::Database(DbError::DatabaseCorrupted));
        }

        Ok(())
    }

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
            if start_epoch > end_epoch + MAX_SIZE_SINGLE_REQUEST_BLOCK_PACKING {
                end_epoch = start_epoch + MAX_SIZE_SINGLE_REQUEST_BLOCK_PACKING
            }

            if let Some(lowest_block_slot) =
                database::get_lowest_beacon_block(&mut conn)?.map(|block| block.slot.as_slot())
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
            // There are no blocks in the `beacon_blocks` database, but there are entries in either
            // `block_packing` table. This is a critical failure. It usually means someone has
            // manually tampered with the database tables and should not occur during normal
            // operation.
            error!("Database is corrupted. Please re-sync the database");
            return Err(Error::Database(DbError::DatabaseCorrupted));
        }

        Ok(())
    }

    // Syncs blockprint data from the blockprint server starting from `current_blockprint_checkpoint`
    // until `end_slot` where `end_slot` is the head of the beacon chain.
    pub async fn sync_blockprint_until(&self, end_slot: Slot) -> Result<(), Error> {
        // Check if blockprint is enabled, otherwise do nothing.
        if let Some(blockprint) = &self.blockprint {
            info!("Syncing new blocks with blockprint");

            let mut conn = database::get_connection(&self.pool)?;
            let start_slot = database::get_current_blockprint_checkpoint(&mut conn)?
                .ok_or(Error::NoBlockprintCheckpointFound)?
                .as_slot();

            let blockprint_head = blockprint.ensure_synced().await?;

            // Don't sync beyond the head according to blockprint.
            let highest_allowed_slot = if blockprint_head < end_slot {
                warn!("Blockprint server behind beacon node");
                blockprint_head
            } else {
                end_slot
            };

            if highest_allowed_slot < start_slot {
                debug!("Blockprint data is up to date");
                return Ok(());
            }

            let blockprints = blockprint
                .blockprint_proposers_between(end_slot, highest_allowed_slot)
                .await?;
            for (index, client) in blockprints {
                database::update_validator_client(&mut conn, index, client.clone())?;
                debug!("Updating blockprint for validator, index: {index}, client: {client}");
            }

            database::update_blockprint_checkpoint(
                &mut conn,
                WatchSlot::from_slot(highest_allowed_slot),
            )?;
        }
        Ok(())
    }
}
