mod config;
mod error;

pub mod compat;
pub mod models;
pub mod schema;
pub mod utils;
pub mod watch_types;

use self::schema::{
    active_config, beacon_blocks, canonical_slots, proposer_info, suboptimal_attestations,
    validators,
};

use diesel::dsl::max;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{Builder, ConnectionManager, Pool, PooledConnection};
use diesel::upsert::excluded;
use log::{debug, info};
use std::collections::HashMap;
use std::time::Instant;
use types::{EthSpec, SignedBeaconBlock};

pub use self::error::Error;
pub use self::models::{WatchBeaconBlock, WatchCanonicalSlot, WatchProposerInfo, WatchValidator};
pub use self::watch_types::{WatchHash, WatchPK, WatchSlot};

pub use crate::block_rewards::{
    get_block_rewards_by_root, get_block_rewards_by_slot, get_highest_block_rewards,
    get_lowest_block_rewards, get_unknown_block_rewards, insert_batch_block_rewards,
    WatchBlockRewards,
};

pub use crate::block_packing::{
    get_block_packing_by_root, get_block_packing_by_slot, get_highest_block_packing,
    get_lowest_block_packing, get_unknown_block_packing, insert_batch_block_packing,
    WatchBlockPacking,
};

pub use crate::suboptimal_attestations::{
    get_all_suboptimal_attestations_for_epoch, get_attestation_by_index, get_attestation_by_pubkey,
    get_highest_attestation, get_lowest_attestation, insert_batch_suboptimal_attestations,
    WatchAttestation, WatchSuboptimalAttestation,
};

pub use crate::blockprint::{
    get_blockprint_by_root, get_blockprint_by_slot, get_highest_blockprint, get_lowest_blockprint,
    get_unknown_blockprint, get_validators_clients_at_slot, insert_batch_blockprint,
    WatchBlockprint,
};

pub use config::Config;

/// Batch inserts cannot exceed a certain size.
/// See https://github.com/diesel-rs/diesel/issues/2414.
/// For some reason, this seems to translate to 65535 / 5 (13107) records.
pub const MAX_SIZE_BATCH_INSERT: usize = 13107;

pub type PgPool = Pool<ConnectionManager<PgConnection>>;
pub type PgConn = PooledConnection<ConnectionManager<PgConnection>>;

/// Connect to a Postgresql database and build a connection pool.
pub fn build_connection_pool(config: &Config) -> Result<PgPool, Error> {
    let database_url = config.clone().build_database_url();
    info!("Building connection pool at: {database_url}");
    let pg = ConnectionManager::<PgConnection>::new(&database_url);
    Builder::new().build(pg).map_err(Error::Pool)
}

/// Retrieve an idle connection from the pool.
pub fn get_connection(pool: &PgPool) -> Result<PgConn, Error> {
    pool.get().map_err(Error::Pool)
}

/// Insert the active config into the database. This is used to check if the connected beacon node
/// is compatible with the database. These values will not change (except
/// `current_blockprint_checkpoint`).
pub fn insert_active_config(
    conn: &mut PgConn,
    new_config_name: String,
    new_slots_per_epoch: u64,
) -> Result<(), Error> {
    use self::active_config::dsl::*;

    diesel::insert_into(active_config)
        .values(&vec![(
            id.eq(1),
            config_name.eq(new_config_name),
            slots_per_epoch.eq(new_slots_per_epoch as i32),
        )])
        .on_conflict_do_nothing()
        .execute(conn)?;

    Ok(())
}

/// Get the active config from the database.
pub fn get_active_config(conn: &mut PgConn) -> Result<Option<(String, i32)>, Error> {
    use self::active_config::dsl::*;
    Ok(active_config
        .select((config_name, slots_per_epoch))
        .filter(id.eq(1))
        .first::<(String, i32)>(conn)
        .optional()?)
}

///
/// INSERT statements
///

/// Inserts a single row into the `canonical_slots` table.
/// If `new_slot.beacon_block` is `None`, the value in the row will be `null`.
///
/// On a conflict, it will do nothing, leaving the old value.
pub fn insert_canonical_slot(conn: &mut PgConn, new_slot: WatchCanonicalSlot) -> Result<(), Error> {
    diesel::insert_into(canonical_slots::table)
        .values(&new_slot)
        .on_conflict_do_nothing()
        .execute(conn)?;

    debug!("Canonical slot inserted: {}", new_slot.slot);
    Ok(())
}

pub fn insert_beacon_block<T: EthSpec>(
    conn: &mut PgConn,
    block: SignedBeaconBlock<T>,
    root: WatchHash,
) -> Result<(), Error> {
    use self::canonical_slots::dsl::{beacon_block, slot as canonical_slot};

    let block_message = block.message();

    // Pull out relevant values from the block.
    let slot = WatchSlot::from_slot(block.slot());
    let parent_root = WatchHash::from_hash(block.parent_root());
    let proposer_index = block_message.proposer_index() as i32;
    let graffiti = block_message.body().graffiti().as_utf8_lossy();
    let attestation_count = block_message.body().attestations().len() as i32;

    let full_payload = block_message.execution_payload().ok();

    let transaction_count: Option<i32> = if let Some(bellatrix_payload) =
        full_payload.and_then(|payload| payload.execution_payload_merge().ok())
    {
        Some(bellatrix_payload.transactions.len() as i32)
    } else {
        full_payload
            .and_then(|payload| payload.execution_payload_capella().ok())
            .map(|payload| payload.transactions.len() as i32)
    };

    let withdrawal_count: Option<i32> = full_payload
        .and_then(|payload| payload.execution_payload_capella().ok())
        .map(|payload| payload.withdrawals.len() as i32);

    let block_to_add = WatchBeaconBlock {
        slot,
        root,
        parent_root,
        attestation_count,
        transaction_count,
        withdrawal_count,
    };

    let proposer_info_to_add = WatchProposerInfo {
        slot,
        proposer_index,
        graffiti,
    };

    // Update the canonical slots table.
    diesel::update(canonical_slots::table)
        .set(beacon_block.eq(root))
        .filter(canonical_slot.eq(slot))
        // Do not overwrite the value if it already exists.
        .filter(beacon_block.is_null())
        .execute(conn)?;

    diesel::insert_into(beacon_blocks::table)
        .values(block_to_add)
        .on_conflict_do_nothing()
        .execute(conn)?;

    diesel::insert_into(proposer_info::table)
        .values(proposer_info_to_add)
        .on_conflict_do_nothing()
        .execute(conn)?;

    debug!("Beacon block inserted at slot: {slot}, root: {root}, parent: {parent_root}");
    Ok(())
}

/// Insert a validator into the `validators` table
///
/// On a conflict, it will only overwrite `status`, `activation_epoch` and `exit_epoch`.
pub fn insert_validator(conn: &mut PgConn, validator: WatchValidator) -> Result<(), Error> {
    use self::validators::dsl::*;
    let new_index = validator.index;
    let new_public_key = validator.public_key;

    diesel::insert_into(validators)
        .values(validator)
        .on_conflict(index)
        .do_update()
        .set((
            status.eq(excluded(status)),
            activation_epoch.eq(excluded(activation_epoch)),
            exit_epoch.eq(excluded(exit_epoch)),
        ))
        .execute(conn)?;

    debug!("Validator inserted, index: {new_index}, public_key: {new_public_key}");
    Ok(())
}

/// Insert a batch of values into the `validators` table.
///
/// On a conflict, it will do nothing.
///
/// Should not be used when updating validators.
/// Validators should be updated through the `insert_validator` function which contains the correct
/// `on_conflict` clauses.
pub fn insert_batch_validators(
    conn: &mut PgConn,
    all_validators: Vec<WatchValidator>,
) -> Result<(), Error> {
    use self::validators::dsl::*;

    let mut count = 0;

    for chunk in all_validators.chunks(1000) {
        count += diesel::insert_into(validators)
            .values(chunk)
            .on_conflict_do_nothing()
            .execute(conn)?;
    }

    debug!("Validators inserted, count: {count}");
    Ok(())
}

///
/// SELECT statements
///

/// Selects a single row of the `canonical_slots` table corresponding to a given `slot_query`.
pub fn get_canonical_slot(
    conn: &mut PgConn,
    slot_query: WatchSlot,
) -> Result<Option<WatchCanonicalSlot>, Error> {
    use self::canonical_slots::dsl::*;
    let timer = Instant::now();

    let result = canonical_slots
        .filter(slot.eq(slot_query))
        .first::<WatchCanonicalSlot>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Canonical slot requested: {slot_query}, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects a single row of the `canonical_slots` table corresponding to a given `root_query`.
/// Only returns the non-skipped slot which matches `root`.
pub fn get_canonical_slot_by_root(
    conn: &mut PgConn,
    root_query: WatchHash,
) -> Result<Option<WatchCanonicalSlot>, Error> {
    use self::canonical_slots::dsl::*;
    let timer = Instant::now();

    let result = canonical_slots
        .filter(root.eq(root_query))
        .filter(skipped.eq(false))
        .first::<WatchCanonicalSlot>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Canonical root requested: {root_query}, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects `root` from a single row of the `canonical_slots` table corresponding to a given
/// `slot_query`.
#[allow(dead_code)]
pub fn get_root_at_slot(
    conn: &mut PgConn,
    slot_query: WatchSlot,
) -> Result<Option<WatchHash>, Error> {
    use self::canonical_slots::dsl::*;
    let timer = Instant::now();

    let result = canonical_slots
        .select(root)
        .filter(slot.eq(slot_query))
        .first::<WatchHash>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Canonical slot requested: {slot_query}, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects `slot` from the row of the `canonical_slots` table corresponding to the minimum value
/// of `slot`.
pub fn get_lowest_canonical_slot(conn: &mut PgConn) -> Result<Option<WatchCanonicalSlot>, Error> {
    use self::canonical_slots::dsl::*;
    let timer = Instant::now();

    let result = canonical_slots
        .order_by(slot.asc())
        .limit(1)
        .first::<WatchCanonicalSlot>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Canonical slot requested: lowest, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects `slot` from the row of the `canonical_slots` table corresponding to the minimum value
/// of `slot` and where `skipped == false`.
pub fn get_lowest_non_skipped_canonical_slot(
    conn: &mut PgConn,
) -> Result<Option<WatchCanonicalSlot>, Error> {
    use self::canonical_slots::dsl::*;
    let timer = Instant::now();

    let result = canonical_slots
        .filter(skipped.eq(false))
        .order_by(slot.asc())
        .limit(1)
        .first::<WatchCanonicalSlot>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Canonical slot requested: lowest_non_skipped, time taken: {time_taken:?})");
    Ok(result)
}

/// Select 'slot' from the row of the `canonical_slots` table corresponding to the maximum value
/// of `slot`.
pub fn get_highest_canonical_slot(conn: &mut PgConn) -> Result<Option<WatchCanonicalSlot>, Error> {
    use self::canonical_slots::dsl::*;
    let timer = Instant::now();

    let result = canonical_slots
        .order_by(slot.desc())
        .limit(1)
        .first::<WatchCanonicalSlot>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Canonical slot requested: highest, time taken: {time_taken:?}");
    Ok(result)
}

/// Select 'slot' from the row of the `canonical_slots` table corresponding to the maximum value
/// of `slot` and where `skipped == false`.
pub fn get_highest_non_skipped_canonical_slot(
    conn: &mut PgConn,
) -> Result<Option<WatchCanonicalSlot>, Error> {
    use self::canonical_slots::dsl::*;
    let timer = Instant::now();

    let result = canonical_slots
        .filter(skipped.eq(false))
        .order_by(slot.desc())
        .limit(1)
        .first::<WatchCanonicalSlot>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Canonical slot requested: highest_non_skipped, time taken: {time_taken:?}");
    Ok(result)
}

/// Select all rows of the `canonical_slots` table where `slot >= `start_slot && slot <=
/// `end_slot`.
pub fn get_canonical_slots_by_range(
    conn: &mut PgConn,
    start_slot: WatchSlot,
    end_slot: WatchSlot,
) -> Result<Option<Vec<WatchCanonicalSlot>>, Error> {
    use self::canonical_slots::dsl::*;
    let timer = Instant::now();

    let result = canonical_slots
        .filter(slot.ge(start_slot))
        .filter(slot.le(end_slot))
        .load::<WatchCanonicalSlot>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!(
        "Canonical slots by range requested, start_slot: {}, end_slot: {}, time_taken: {:?}",
        start_slot.as_u64(),
        end_slot.as_u64(),
        time_taken
    );
    Ok(result)
}

/// Selects `root` from all rows of the `canonical_slots` table which have `beacon_block == null`
/// and `skipped == false`
pub fn get_unknown_canonical_blocks(conn: &mut PgConn) -> Result<Vec<WatchHash>, Error> {
    use self::canonical_slots::dsl::*;

    let result = canonical_slots
        .select(root)
        .filter(beacon_block.is_null())
        .filter(skipped.eq(false))
        .order_by(slot.desc())
        .load::<WatchHash>(conn)?;

    Ok(result)
}

/// Selects the row from the `beacon_blocks` table where `slot` is minimum.
pub fn get_lowest_beacon_block(conn: &mut PgConn) -> Result<Option<WatchBeaconBlock>, Error> {
    use self::beacon_blocks::dsl::*;
    let timer = Instant::now();

    let result = beacon_blocks
        .order_by(slot.asc())
        .limit(1)
        .first::<WatchBeaconBlock>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Beacon block requested: lowest, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects the row from the `beacon_blocks` table where `slot` is maximum.
pub fn get_highest_beacon_block(conn: &mut PgConn) -> Result<Option<WatchBeaconBlock>, Error> {
    use self::beacon_blocks::dsl::*;
    let timer = Instant::now();

    let result = beacon_blocks
        .order_by(slot.desc())
        .limit(1)
        .first::<WatchBeaconBlock>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Beacon block requested: highest, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects a single row from the `beacon_blocks` table corresponding to a given `root_query`.
pub fn get_beacon_block_by_root(
    conn: &mut PgConn,
    root_query: WatchHash,
) -> Result<Option<WatchBeaconBlock>, Error> {
    use self::beacon_blocks::dsl::*;
    let timer = Instant::now();

    let result = beacon_blocks
        .filter(root.eq(root_query))
        .first::<WatchBeaconBlock>(conn)
        .optional()?;
    let time_taken = timer.elapsed();
    debug!("Beacon block requested: {root_query}, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects a single row from the `beacon_blocks` table corresponding to a given `slot_query`.
pub fn get_beacon_block_by_slot(
    conn: &mut PgConn,
    slot_query: WatchSlot,
) -> Result<Option<WatchBeaconBlock>, Error> {
    use self::beacon_blocks::dsl::*;
    let timer = Instant::now();

    let result = beacon_blocks
        .filter(slot.eq(slot_query))
        .first::<WatchBeaconBlock>(conn)
        .optional()?;
    let time_taken = timer.elapsed();
    debug!("Beacon block requested: {slot_query}, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects the row from the `beacon_blocks` table where `parent_root` equals the given `parent`.
/// This fetches the next block in the database.
///
/// Will return `Ok(None)` if there are no matching blocks (e.g. the tip of the chain).
pub fn get_beacon_block_with_parent(
    conn: &mut PgConn,
    parent: WatchHash,
) -> Result<Option<WatchBeaconBlock>, Error> {
    use self::beacon_blocks::dsl::*;
    let timer = Instant::now();

    let result = beacon_blocks
        .filter(parent_root.eq(parent))
        .first::<WatchBeaconBlock>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Next beacon block requested: {parent}, time taken: {time_taken:?}");
    Ok(result)
}

/// Select all rows of the `beacon_blocks` table where `slot >= `start_slot && slot <=
/// `end_slot`.
pub fn get_beacon_blocks_by_range(
    conn: &mut PgConn,
    start_slot: WatchSlot,
    end_slot: WatchSlot,
) -> Result<Option<Vec<WatchBeaconBlock>>, Error> {
    use self::beacon_blocks::dsl::*;
    let timer = Instant::now();

    let result = beacon_blocks
        .filter(slot.ge(start_slot))
        .filter(slot.le(end_slot))
        .load::<WatchBeaconBlock>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Beacon blocks by range requested, start_slot: {start_slot}, end_slot: {end_slot}, time_taken: {time_taken:?}");
    Ok(result)
}

/// Selects a single row of the `proposer_info` table corresponding to a given `root_query`.
pub fn get_proposer_info_by_root(
    conn: &mut PgConn,
    root_query: WatchHash,
) -> Result<Option<WatchProposerInfo>, Error> {
    use self::beacon_blocks::dsl::{beacon_blocks, root};
    use self::proposer_info::dsl::*;
    let timer = Instant::now();

    let join = beacon_blocks.inner_join(proposer_info);

    let result = join
        .select((slot, proposer_index, graffiti))
        .filter(root.eq(root_query))
        .first::<WatchProposerInfo>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Proposer info requested for block: {root_query}, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects a single row of the `proposer_info` table corresponding to a given `slot_query`.
pub fn get_proposer_info_by_slot(
    conn: &mut PgConn,
    slot_query: WatchSlot,
) -> Result<Option<WatchProposerInfo>, Error> {
    use self::proposer_info::dsl::*;
    let timer = Instant::now();

    let result = proposer_info
        .filter(slot.eq(slot_query))
        .first::<WatchProposerInfo>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Proposer info requested for slot: {slot_query}, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects multiple rows of the `proposer_info` table between `start_slot` and `end_slot`.
/// Selects a single row of the `proposer_info` table corresponding to a given `slot_query`.
#[allow(dead_code)]
pub fn get_proposer_info_by_range(
    conn: &mut PgConn,
    start_slot: WatchSlot,
    end_slot: WatchSlot,
) -> Result<Option<Vec<WatchProposerInfo>>, Error> {
    use self::proposer_info::dsl::*;
    let timer = Instant::now();

    let result = proposer_info
        .filter(slot.ge(start_slot))
        .filter(slot.le(end_slot))
        .load::<WatchProposerInfo>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!(
        "Proposer info requested for range: {start_slot} to {end_slot}, time taken: {time_taken:?}"
    );
    Ok(result)
}

pub fn get_validators_latest_proposer_info(
    conn: &mut PgConn,
    indices_query: Vec<i32>,
) -> Result<HashMap<i32, WatchProposerInfo>, Error> {
    use self::proposer_info::dsl::*;

    let proposers = proposer_info
        .filter(proposer_index.eq_any(indices_query))
        .load::<WatchProposerInfo>(conn)?;

    let mut result = HashMap::new();
    for proposer in proposers {
        result
            .entry(proposer.proposer_index)
            .or_insert_with(|| proposer.clone());
        let entry = result
            .get_mut(&proposer.proposer_index)
            .ok_or_else(|| Error::Other("An internal error occured".to_string()))?;
        if proposer.slot > entry.slot {
            entry.slot = proposer.slot
        }
    }

    Ok(result)
}

/// Selects the max(`slot`) and `proposer_index` of each unique index in the
/// `proposer_info` table and returns them formatted as a `HashMap`.
/// Only returns rows which have `slot <= target_slot`.
///
/// Ideally, this would return the full row, but I have not found a way to do that without using
/// a much more expensive SQL query.
pub fn get_all_validators_latest_proposer_info_at_slot(
    conn: &mut PgConn,
    target_slot: WatchSlot,
) -> Result<HashMap<WatchSlot, i32>, Error> {
    use self::proposer_info::dsl::*;

    let latest_proposals: Vec<(i32, Option<WatchSlot>)> = proposer_info
        .group_by(proposer_index)
        .select((proposer_index, max(slot)))
        .filter(slot.le(target_slot))
        .load::<(i32, Option<WatchSlot>)>(conn)?;

    let mut result = HashMap::new();

    for proposal in latest_proposals {
        if let Some(latest_slot) = proposal.1 {
            result.insert(latest_slot, proposal.0);
        }
    }

    Ok(result)
}

/// Selects a single row from the `validators` table corresponding to a given
/// `validator_index_query`.
pub fn get_validator_by_index(
    conn: &mut PgConn,
    validator_index_query: i32,
) -> Result<Option<WatchValidator>, Error> {
    use self::validators::dsl::*;
    let timer = Instant::now();

    let result = validators
        .filter(index.eq(validator_index_query))
        .first::<WatchValidator>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Validator requested: {validator_index_query}, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects a single row from the `validators` table corresponding to a given
/// `public_key_query`.
pub fn get_validator_by_public_key(
    conn: &mut PgConn,
    public_key_query: WatchPK,
) -> Result<Option<WatchValidator>, Error> {
    use self::validators::dsl::*;
    let timer = Instant::now();

    let result = validators
        .filter(public_key.eq(public_key_query))
        .first::<WatchValidator>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Validator requested: {public_key_query}, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects all rows from the `validators` table which have an `index` contained in
/// the `indices_query`.
#[allow(dead_code)]
pub fn get_validators_by_indices(
    conn: &mut PgConn,
    indices_query: Vec<i32>,
) -> Result<Vec<WatchValidator>, Error> {
    use self::validators::dsl::*;
    let timer = Instant::now();

    let query_len = indices_query.len();
    let result = validators
        .filter(index.eq_any(indices_query))
        .load::<WatchValidator>(conn)?;

    let time_taken = timer.elapsed();
    debug!("{query_len} validators requested, time taken: {time_taken:?}");
    Ok(result)
}

// Selects all rows from the `validators` table.
pub fn get_all_validators(conn: &mut PgConn) -> Result<Vec<WatchValidator>, Error> {
    use self::validators::dsl::*;
    let timer = Instant::now();

    let result = validators.load::<WatchValidator>(conn)?;

    let time_taken = timer.elapsed();
    debug!("All validators requested, time taken: {time_taken:?}");
    Ok(result)
}

/// Counts the number of rows in the `validators` table.
#[allow(dead_code)]
pub fn count_validators(conn: &mut PgConn) -> Result<i64, Error> {
    use self::validators::dsl::*;

    validators.count().get_result(conn).map_err(Error::Database)
}

/// Counts the number of rows in the `validators` table where
/// `activation_epoch <= target_slot.epoch()`.
pub fn count_validators_activated_before_slot(
    conn: &mut PgConn,
    target_slot: WatchSlot,
    slots_per_epoch: u64,
) -> Result<i64, Error> {
    use self::validators::dsl::*;

    let target_epoch = target_slot.epoch(slots_per_epoch);

    validators
        .count()
        .filter(activation_epoch.le(target_epoch.as_u64() as i32))
        .get_result(conn)
        .map_err(Error::Database)
}

///
/// DELETE statements.
///

/// Deletes all rows of the `canonical_slots` table which have `slot` greater than `slot_query`.
///
/// Due to the ON DELETE CASCADE clause present in the database migration SQL, deleting rows from
/// `canonical_slots` will delete all corresponding rows in `beacon_blocks, `block_rewards`,
/// `block_packing` and `proposer_info`.
pub fn delete_canonical_slots_above(
    conn: &mut PgConn,
    slot_query: WatchSlot,
) -> Result<usize, Error> {
    use self::canonical_slots::dsl::*;

    let result = diesel::delete(canonical_slots)
        .filter(slot.gt(slot_query))
        .execute(conn)?;

    debug!("Deleted canonical slots above {slot_query}: {result} rows deleted");
    Ok(result)
}

/// Deletes all rows of the `suboptimal_attestations` table which have `epoch_start_slot` greater
/// than `epoch_start_slot_query`.
pub fn delete_suboptimal_attestations_above(
    conn: &mut PgConn,
    epoch_start_slot_query: WatchSlot,
) -> Result<usize, Error> {
    use self::suboptimal_attestations::dsl::*;

    let result = diesel::delete(suboptimal_attestations)
        .filter(epoch_start_slot.gt(epoch_start_slot_query))
        .execute(conn)?;

    debug!("Deleted attestations above: {epoch_start_slot_query}, rows deleted: {result}");
    Ok(result)
}
