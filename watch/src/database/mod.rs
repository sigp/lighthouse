#![allow(dead_code)]

use self::schema::{
    beacon_blocks, block_packing, block_rewards, canonical_slots, proposer_info,
    suboptimal_attestations, validators,
};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{Builder, ConnectionManager, Pool, PooledConnection};
use diesel::upsert::excluded;
use log::{debug, info};
use std::time::Instant;

pub use self::error::Error;
pub use self::models::{
    WatchBeaconBlock, WatchBlockPacking, WatchBlockRewards, WatchCanonicalSlot, WatchProposerInfo,
    WatchSuboptimalAttestation, WatchValidator,
};
pub use self::watch_types::{WatchAttestation, WatchHash, WatchPK, WatchSlot};
pub use config::Config;
pub use types::{BeaconBlockHeader, Epoch, Hash256, Slot};

mod config;
mod error;

pub mod compat;
pub mod models;
pub mod schema;
pub mod utils;
pub mod watch_types;

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

/// Inserts a single row into the `beacon_blocks` table.
/// The value is derived from the value of the given block `root` and `BeaconBlockHeader`.
///
/// On a conflict, it will do nothing, leaving the old value.
///
/// This additionally runs an UPDATE on the `canonical_slots` table so that it fills in
/// `beacon_block` with the given block `root`.
pub fn insert_beacon_block_from_header(
    conn: &mut PgConn,
    header: &BeaconBlockHeader,
    root: WatchHash,
) -> Result<(), Error> {
    use self::beacon_blocks::dsl::{parent_root, root as block_root, slot as block_slot};
    use self::canonical_slots::dsl::{beacon_block, slot as canonical_slot};

    let slot = WatchSlot::from_slot(header.slot);
    let parent = WatchHash::from_hash(header.parent_root);

    // Update `canonical_slots` first since the `beacon_blocks` table relies on the value of
    // `beacon_block`.
    diesel::update(canonical_slots::table)
        .set(beacon_block.eq(root))
        .filter(canonical_slot.eq(slot))
        // Do not overwrite the value if it already exists.
        .filter(beacon_block.is_null())
        .execute(conn)?;

    diesel::insert_into(beacon_blocks::table)
        .values((
            block_slot.eq(slot),
            block_root.eq(root),
            parent_root.eq(parent),
        ))
        .on_conflict_do_nothing()
        .execute(conn)?;

    debug!("Beacon block inserted at slot: {slot}, root: {root}, parent: {parent}");
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
/// TODO(mac): If a validator exits, there will be a conflict on
/// `exit_epoch`. Need to catch this conflict and update it.
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

/// Insert a batch of values into the `suboptimal_attestations` table
///
/// Since attestations technically occur per-slot but we only store them per-epoch (via its
/// `start_slot`) so if any slot in the epoch changes, we need to resync the whole epoch as a
/// 'suboptimal' attestation could now be 'optimal'.
///
/// This is handled in the update code, where in the case of a re-org, the affected epoch is
/// deleted completely.
///
/// On a conflict, it will do nothing.
pub fn insert_batch_suboptimal_attestations(
    conn: &mut PgConn,
    attestations: Vec<WatchSuboptimalAttestation>,
) -> Result<(), Error> {
    use self::suboptimal_attestations::dsl::*;

    let mut count = 0;
    let timer = Instant::now();

    for chunk in attestations.chunks(MAX_SIZE_BATCH_INSERT) {
        count += diesel::insert_into(suboptimal_attestations)
            .values(chunk)
            .on_conflict_do_nothing()
            .execute(conn)?;
    }

    let time_taken = timer.elapsed();
    debug!("Attestations inserted, count: {count}, time taken: {time_taken:?}");
    Ok(())
}

/// Insert a batch of values into the `proposer_info` table.
///
/// On a conflict, it will do nothing, leaving the old value.
pub fn insert_batch_proposer_info(
    conn: &mut PgConn,
    info: Vec<WatchProposerInfo>,
) -> Result<(), Error> {
    use self::proposer_info::dsl::*;

    let mut count = 0;
    let timer = Instant::now();

    for chunk in info.chunks(MAX_SIZE_BATCH_INSERT) {
        count += diesel::insert_into(proposer_info)
            .values(chunk)
            .on_conflict_do_nothing()
            .execute(conn)?;
    }

    let time_taken = timer.elapsed();
    debug!("Proposer info inserted, count: {count}, time taken: {time_taken:?}");
    Ok(())
}

/// Insert a batch of values into the `block_rewards` table.
///
/// On a conflict, it will do nothing, leaving the old value.
pub fn insert_batch_block_rewards(
    conn: &mut PgConn,
    rewards: Vec<WatchBlockRewards>,
) -> Result<(), Error> {
    use self::block_rewards::dsl::*;

    let mut count = 0;
    let timer = Instant::now();

    for chunk in rewards.chunks(MAX_SIZE_BATCH_INSERT) {
        count += diesel::insert_into(block_rewards)
            .values(chunk)
            .on_conflict_do_nothing()
            .execute(conn)?;
    }

    let time_taken = timer.elapsed();
    debug!("Block rewards inserted, count: {count}, time_taken: {time_taken:?}");
    Ok(())
}

/// Insert a batch of values into the `block_packing` table.
///
/// On a conflict, it will do nothing, leaving the old value.
pub fn insert_batch_block_packing(
    conn: &mut PgConn,
    packing: Vec<WatchBlockPacking>,
) -> Result<(), Error> {
    use self::block_packing::dsl::*;

    let mut count = 0;
    let timer = Instant::now();

    for chunk in packing.chunks(MAX_SIZE_BATCH_INSERT) {
        count += diesel::insert_into(block_packing)
            .values(chunk)
            .on_conflict_do_nothing()
            .execute(conn)?;
    }

    let time_taken = timer.elapsed();
    debug!("Block packing inserted, count: {count}, time taken: {time_taken:?}");
    Ok(())
}

///
/// UPDATE statements
///

/// Updates the `client` column for a single row of the `validators` table corresponding to a given `index_query`.
/// Updates the value of `client` to the value of `updated_client`.
pub fn update_validator_client(
    conn: &mut PgConn,
    index_query: i32,
    updated_client: String,
) -> Result<(), Error> {
    use self::validators::dsl::*;

    let timer = Instant::now();

    diesel::update(validators)
        .set(client.eq(updated_client))
        .filter(index.eq(index_query))
        .execute(conn)?;

    let time_taken = timer.elapsed();
    debug!("Validator updated, time taken: {time_taken:?}");
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

// Selects all rows from the `validators` table.
pub fn get_all_validators(conn: &mut PgConn) -> Result<Vec<WatchValidator>, Error> {
    use self::validators::dsl::*;
    let timer = Instant::now();

    let result = validators.load::<WatchValidator>(conn)?;

    let time_taken = timer.elapsed();
    debug!("All validators requested, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects the row from the `suboptimal_attestations` table where `epoch_start_slot` is minimum.
pub fn get_lowest_attestation(
    conn: &mut PgConn,
) -> Result<Option<WatchSuboptimalAttestation>, Error> {
    use self::suboptimal_attestations::dsl::*;

    Ok(suboptimal_attestations
        .order_by(epoch_start_slot.asc())
        .limit(1)
        .first::<WatchSuboptimalAttestation>(conn)
        .optional()?)
}

/// Selects the row from the `suboptimal_attestations` table where `epoch_start_slot` is maximum.
pub fn get_highest_attestation(
    conn: &mut PgConn,
) -> Result<Option<WatchSuboptimalAttestation>, Error> {
    use self::suboptimal_attestations::dsl::*;

    Ok(suboptimal_attestations
        .order_by(epoch_start_slot.desc())
        .limit(1)
        .first::<WatchSuboptimalAttestation>(conn)
        .optional()?)
}

/// Selects a single row from the `suboptimal_attestations` table corresponding to a given
/// `index_query` and `epoch_query`.
pub fn get_attestation_by_index(
    conn: &mut PgConn,
    index_query: i32,
    epoch_query: Epoch,
    slots_per_epoch: u64,
) -> Result<Option<WatchSuboptimalAttestation>, Error> {
    use self::suboptimal_attestations::dsl::*;
    let timer = Instant::now();

    let result = suboptimal_attestations
        .filter(epoch_start_slot.eq(WatchSlot::from_slot(
            epoch_query.start_slot(slots_per_epoch),
        )))
        .filter(index.eq(index_query))
        .first::<WatchSuboptimalAttestation>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Attestation requested for validator: {index_query}, epoch: {epoch_query}, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects a single row from the `suboptimal_attestations` table corresponding to a given
/// `pubkey_query` and `epoch_query`.
pub fn get_attestation_by_pubkey(
    conn: &mut PgConn,
    pubkey_query: WatchPK,
    epoch_query: Epoch,
    slots_per_epoch: u64,
) -> Result<Option<WatchSuboptimalAttestation>, Error> {
    use self::suboptimal_attestations::dsl::*;
    use self::validators::dsl::{public_key, validators};
    let timer = Instant::now();

    let join = validators.inner_join(suboptimal_attestations);

    let result = join
        .select((epoch_start_slot, index, source, head, target))
        .filter(epoch_start_slot.eq(WatchSlot::from_slot(
            epoch_query.start_slot(slots_per_epoch),
        )))
        .filter(public_key.eq(pubkey_query))
        .first::<WatchSuboptimalAttestation>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Attestation requested for validator: {pubkey_query}, epoch: {epoch_query}, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects the row from the `proposer_info` table where `slot` is minimum.
pub fn get_lowest_proposer_info(conn: &mut PgConn) -> Result<Option<WatchProposerInfo>, Error> {
    use self::proposer_info::dsl::*;
    let timer = Instant::now();

    let result = proposer_info
        .order_by(slot.asc())
        .limit(1)
        .first::<WatchProposerInfo>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Proposer info requested for block: lowest, time taken: {time_taken:?}");
    Ok(result)
}

/// Selects the row from the `proposer_info` table where `slot` is maximum.
pub fn get_highest_proposer_info(conn: &mut PgConn) -> Result<Option<WatchProposerInfo>, Error> {
    use self::proposer_info::dsl::*;
    let timer = Instant::now();

    let result = proposer_info
        .order_by(slot.desc())
        .limit(1)
        .first::<WatchProposerInfo>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Proposer info requested for block: highest, time taken: {time_taken:?}");
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

/// Selects the row from the `block_rewards` table where `slot` is minimum.
pub fn get_lowest_block_rewards(conn: &mut PgConn) -> Result<Option<WatchBlockRewards>, Error> {
    use self::block_rewards::dsl::*;
    let timer = Instant::now();

    let result = block_rewards
        .order_by(slot.asc())
        .limit(1)
        .first::<WatchBlockRewards>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Block rewards requested: lowest, time_taken: {time_taken:?}");
    Ok(result)
}

/// Selects the row from the `block_rewards` table where `slot` is maximum.
pub fn get_highest_block_rewards(conn: &mut PgConn) -> Result<Option<WatchBlockRewards>, Error> {
    use self::block_rewards::dsl::*;
    let timer = Instant::now();

    let result = block_rewards
        .order_by(slot.desc())
        .limit(1)
        .first::<WatchBlockRewards>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Block rewards requested: highest, time_taken: {time_taken:?}");
    Ok(result)
}

/// Selects a single row of the `block_rewards` table corresponding to a given `root_query`.
pub fn get_block_reward_by_root(
    conn: &mut PgConn,
    root_query: WatchHash,
) -> Result<Option<WatchBlockRewards>, Error> {
    use self::beacon_blocks::dsl::{beacon_blocks, root};
    use self::block_rewards::dsl::*;
    let timer = Instant::now();

    let join = beacon_blocks.inner_join(block_rewards);

    let result = join
        .select((slot, total, attestation_reward, sync_committee_reward))
        .filter(root.eq(root_query))
        .first::<WatchBlockRewards>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Block rewards requested: {root_query}, time_taken: {time_taken:?}");
    Ok(result)
}

/// Selects a single row of the `block_rewards` table corresponding to a given `slot_query`.
pub fn get_block_reward_by_slot(
    conn: &mut PgConn,
    slot_query: WatchSlot,
) -> Result<Option<WatchBlockRewards>, Error> {
    use self::block_rewards::dsl::*;
    let timer = Instant::now();

    let result = block_rewards
        .filter(slot.eq(slot_query))
        .first::<WatchBlockRewards>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Block rewards requested: {slot_query}, time_taken: {time_taken:?}");
    Ok(result)
}

/// Selects `slot` from all rows of the `beacon_blocks` table which do not have a corresponding
/// row in `block_rewards`.
pub fn get_unknown_block_rewards(conn: &mut PgConn) -> Result<Vec<Option<WatchSlot>>, Error> {
    use self::beacon_blocks::dsl::{beacon_blocks, root, slot};
    use self::block_rewards::dsl::block_rewards;

    let join = beacon_blocks.left_join(block_rewards);

    let result = join
        .select(slot)
        .filter(root.is_null())
        // Block rewards cannot be retrieved for `slot == 0` so we need to exclude it.
        .filter(slot.ne(0))
        .order_by(slot.desc())
        .nullable()
        .load::<Option<WatchSlot>>(conn)?;

    Ok(result)
}

/// Selects the row from the `block_packing` table where `slot` is minimum.
pub fn get_lowest_block_packing(conn: &mut PgConn) -> Result<Option<WatchBlockPacking>, Error> {
    use self::block_packing::dsl::*;
    let timer = Instant::now();

    let result = block_packing
        .order_by(slot.asc())
        .limit(1)
        .first::<WatchBlockPacking>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Block packing requested: lowest, time_taken: {time_taken:?}");
    Ok(result)
}

/// Selects the row from the `block_packing` table where `slot` is maximum.
pub fn get_highest_block_packing(conn: &mut PgConn) -> Result<Option<WatchBlockPacking>, Error> {
    use self::block_packing::dsl::*;
    let timer = Instant::now();

    let result = block_packing
        .order_by(slot.desc())
        .limit(1)
        .first::<WatchBlockPacking>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Block packing requested: highest, time_taken: {time_taken:?}");
    Ok(result)
}

/// Selects a single row of the `block_packing` table corresponding to a given `root_query`.
pub fn get_block_packing_by_root(
    conn: &mut PgConn,
    root_query: WatchHash,
) -> Result<Option<WatchBlockPacking>, Error> {
    use self::beacon_blocks::dsl::{beacon_blocks, root};
    use self::block_packing::dsl::*;
    let timer = Instant::now();

    let join = beacon_blocks.inner_join(block_packing);

    let result = join
        .select((slot, available, included, prior_skip_slots))
        .filter(root.eq(root_query))
        .first::<WatchBlockPacking>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Block packing requested: {root_query}, time_taken: {time_taken:?}");
    Ok(result)
}

/// Selects a single row of the `block_packing` table corresponding to a given `slot_query`.
pub fn get_block_packing_by_slot(
    conn: &mut PgConn,
    slot_query: WatchSlot,
) -> Result<Option<WatchBlockPacking>, Error> {
    use self::block_packing::dsl::*;
    let timer = Instant::now();

    let result = block_packing
        .filter(slot.eq(slot_query))
        .first::<WatchBlockPacking>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Block packing requested: {slot_query}, time_taken: {time_taken:?}");
    Ok(result)
}

/// Selects `slot` from all rows of the `beacon_blocks` table which do not have a corresponding
/// row in `block_packing`.
pub fn get_unknown_block_packing(
    conn: &mut PgConn,
    slots_per_epoch: i32,
) -> Result<Vec<Option<WatchSlot>>, Error> {
    use self::beacon_blocks::dsl::{beacon_blocks, root, slot};
    use self::block_packing::dsl::block_packing;

    let join = beacon_blocks.left_join(block_packing);

    let result = join
        .select(slot)
        .filter(root.is_null())
        // Block packing cannot be retrieved for epoch 0 so we need to exclude them.
        .filter(slot.ge(slots_per_epoch))
        .order_by(slot.desc())
        .nullable()
        .load::<Option<WatchSlot>>(conn)?;

    Ok(result)
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
