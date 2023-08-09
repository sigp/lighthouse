use crate::blockprint::WatchBlockprintClient;
use crate::config::Config as FullConfig;
use crate::database::{self, PgPool, WatchCanonicalSlot, WatchHash, WatchSlot};
use crate::updater::{Config, Error, WatchSpec};
use beacon_node::beacon_chain::BeaconChainError;
use eth2::{
    types::{BlockId, SyncingData},
    BeaconNodeHttpClient, SensitiveUrl,
};
use log::{debug, error, info, warn};
use std::collections::HashSet;
use std::iter::FromIterator;
use types::{BeaconBlockHeader, EthSpec, Hash256, SignedBeaconBlock, Slot};

use crate::updater::{get_beacon_block, get_header, get_validators};

const MAX_EXPECTED_REORG_LENGTH: u64 = 32;

/// Ensure the existing database is valid for this run.
pub async fn ensure_valid_database<T: EthSpec>(
    spec: &WatchSpec<T>,
    pool: &mut PgPool,
) -> Result<(), Error> {
    let mut conn = database::get_connection(pool)?;

    let bn_slots_per_epoch = spec.slots_per_epoch();
    let bn_config_name = spec.network.clone();

    if let Some((db_config_name, db_slots_per_epoch)) = database::get_active_config(&mut conn)? {
        if db_config_name != bn_config_name || db_slots_per_epoch != bn_slots_per_epoch as i32 {
            Err(Error::InvalidConfig(
                "The config stored in the database does not match the beacon node.".to_string(),
            ))
        } else {
            // Configs match.
            Ok(())
        }
    } else {
        // No config exists in the DB.
        database::insert_active_config(&mut conn, bn_config_name, bn_slots_per_epoch)?;
        Ok(())
    }
}

pub struct UpdateHandler<T: EthSpec> {
    pub pool: PgPool,
    pub bn: BeaconNodeHttpClient,
    pub blockprint: Option<WatchBlockprintClient>,
    pub config: Config,
    pub slots_per_epoch: u64,
    pub spec: WatchSpec<T>,
}

impl<T: EthSpec> UpdateHandler<T> {
    pub async fn new(
        bn: BeaconNodeHttpClient,
        spec: WatchSpec<T>,
        config: FullConfig,
    ) -> Result<UpdateHandler<T>, Error> {
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

        ensure_valid_database(&spec, &mut pool).await?;

        Ok(Self {
            pool,
            bn,
            blockprint,
            config: config.updater,
            slots_per_epoch: spec.slots_per_epoch(),
            spec,
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
            let block_opt: Option<SignedBeaconBlock<T>> =
                get_beacon_block(&self.bn, BlockId::Root(root.as_hash())).await?;
            if let Some(block) = block_opt {
                database::insert_beacon_block(&mut conn, block, root)?;
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
            //self.sync_blockprint_until(start_slot).await?;
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
        let validators = Vec::from_iter(get_validators(&self.bn).await?);

        database::insert_batch_validators(&mut conn, validators)?;

        Ok(())
    }
}
