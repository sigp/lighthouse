use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{Builder, ConnectionManager, Pool, PooledConnection};
use log::{debug, info};

pub use self::error::Error;
pub use self::models::{
    WatchBeaconBlock, WatchBlockPacking, WatchBlockRewards, WatchCanonicalSlot, WatchProposerInfo,
    WatchValidator,
};
use self::schema::{beacon_blocks, block_packing, block_rewards, canonical_slots, proposer_info};
pub use self::watch_types::{WatchHash, WatchPK, WatchSlot};

pub use config::Config;
pub use types::{BeaconBlockHeader, Epoch, Hash256, Slot};

mod config;
mod error;

pub mod compat;
pub mod models;
pub mod schema;
pub mod utils;
pub mod watch_types;

pub type PgPool = Pool<ConnectionManager<PgConnection>>;
pub type PgConn = PooledConnection<ConnectionManager<PgConnection>>;

/// Connect to a Postgresql database and build a connection pool.
pub fn build_connection_pool(config: &Config) -> Result<PgPool, Error> {
    let database_url = config.clone().build_database_url();
    info!("Building connection pool at: {}", database_url);
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

    debug!(
        "Beacon block inserted at slot: {}, root: {}, parent: {}",
        slot, root, parent
    );
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

    let count = diesel::insert_into(proposer_info)
        .values(info)
        .on_conflict_do_nothing()
        .execute(conn)?;

    debug!("Proposer info inserted, count: {}", count);
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

    let count = diesel::insert_into(block_rewards)
        .values(rewards)
        .on_conflict_do_nothing()
        .execute(conn)?;

    debug!("Block rewards inserted, count: {}", count);
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

    let count = diesel::insert_into(block_packing)
        .values(packing)
        .on_conflict_do_nothing()
        .execute(conn)?;

    debug!("Block packing inserted, count: {}", count);
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

    let result = canonical_slots
        .filter(slot.eq(slot_query))
        .first::<WatchCanonicalSlot>(conn)
        .optional()?;

    debug!("Canonical slot read: {}", slot_query);
    Ok(result)
}

/// Selects a single row of the `canonical_slots` table corresponding to a given `root_query`.
/// Only returns the non-skipped slot which matches `root`.
pub fn get_canonical_slot_by_root(
    conn: &mut PgConn,
    root_query: WatchHash,
) -> Result<Option<WatchCanonicalSlot>, Error> {
    use self::canonical_slots::dsl::*;

    let result = canonical_slots
        .filter(root.eq(root_query))
        .filter(skipped.eq(false))
        .first::<WatchCanonicalSlot>(conn)
        .optional()?;

    debug!("Canonical root read: {}", root_query);
    Ok(result)
}

/// Selects `root` from a single row of the `canonical_slots` table corresponding to a given
/// `slot_query`.
pub fn get_root_at_slot(
    conn: &mut PgConn,
    slot_query: WatchSlot,
) -> Result<Option<WatchHash>, Error> {
    use self::canonical_slots::dsl::*;

    let result = canonical_slots
        .select(root)
        .filter(slot.eq(slot_query))
        .first::<WatchHash>(conn)
        .optional()?;

    Ok(result)
}

/// Selects `slot` from the row of the `canonical_slots` table corresponding to the minimum value
/// of `slot`.
pub fn get_lowest_canonical_slot(conn: &mut PgConn) -> Result<Option<WatchCanonicalSlot>, Error> {
    use self::canonical_slots::dsl::*;

    let result = canonical_slots
        .order_by(slot.asc())
        .limit(1)
        .first::<WatchCanonicalSlot>(conn)
        .optional()?;

    Ok(result)
}

/// Selects `slot` from the row of the `canonical_slots` table corresponding to the minimum value
/// of `slot` and where `skipped == false`.
pub fn get_lowest_non_skipped_canonical_slot(
    conn: &mut PgConn,
) -> Result<Option<WatchCanonicalSlot>, Error> {
    use self::canonical_slots::dsl::*;

    let result = canonical_slots
        .filter(skipped.eq(false))
        .order_by(slot.asc())
        .limit(1)
        .first::<WatchCanonicalSlot>(conn)
        .optional()?;

    Ok(result)
}

/// Select 'slot' from the row of the `canonical_slots` table corresponding to the maximum value
/// of `slot`.
pub fn get_highest_canonical_slot(conn: &mut PgConn) -> Result<Option<WatchCanonicalSlot>, Error> {
    use self::canonical_slots::dsl::*;

    let result = canonical_slots
        .order_by(slot.desc())
        .limit(1)
        .first::<WatchCanonicalSlot>(conn)
        .optional()?;

    Ok(result)
}

/// Select 'slot' from the row of the `canonical_slots` table corresponding to the maximum value
/// of `slot` and where `skipped == false`.
pub fn get_highest_non_skipped_canonical_slot(
    conn: &mut PgConn,
) -> Result<Option<WatchCanonicalSlot>, Error> {
    use self::canonical_slots::dsl::*;

    let result = canonical_slots
        .filter(skipped.eq(false))
        .order_by(slot.desc())
        .limit(1)
        .first::<WatchCanonicalSlot>(conn)
        .optional()?;

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

    let result = beacon_blocks
        .order_by(slot.asc())
        .limit(1)
        .first::<WatchBeaconBlock>(conn)
        .optional()?;

    Ok(result)
}

/// Selects the row from the `beacon_blocks` table where `slot` is maximum.
pub fn get_highest_beacon_block(conn: &mut PgConn) -> Result<Option<WatchBeaconBlock>, Error> {
    use self::beacon_blocks::dsl::*;

    let result = beacon_blocks
        .order_by(slot.desc())
        .limit(1)
        .first::<WatchBeaconBlock>(conn)
        .optional()?;

    Ok(result)
}

/// Selects a single row from the `beacon_blocks` table corresponding to a given `root_query`.
pub fn get_beacon_block_by_root(
    conn: &mut PgConn,
    root_query: WatchHash,
) -> Result<Option<WatchBeaconBlock>, Error> {
    use self::beacon_blocks::dsl::*;

    let result = beacon_blocks
        .filter(root.eq(root_query))
        .first::<WatchBeaconBlock>(conn)
        .optional()?;

    Ok(result)
}

/// Selects a single row from the `beacon_blocks` table corresponding to a given `slot_query`.
pub fn get_beacon_block_by_slot(
    conn: &mut PgConn,
    slot_query: WatchSlot,
) -> Result<Option<WatchBeaconBlock>, Error> {
    use self::beacon_blocks::dsl::*;

    let result = beacon_blocks
        .filter(slot.eq(slot_query))
        .first::<WatchBeaconBlock>(conn)
        .optional()?;

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

    let result = beacon_blocks
        .filter(parent_root.eq(parent))
        .first::<WatchBeaconBlock>(conn)
        .optional()?;

    Ok(result)
}

/// Selects the row from the `proposer_info` table where `slot` is minimum.
pub fn get_lowest_proposer_info(conn: &mut PgConn) -> Result<Option<WatchProposerInfo>, Error> {
    use self::proposer_info::dsl::*;

    let result = proposer_info
        .order_by(slot.asc())
        .limit(1)
        .first::<WatchProposerInfo>(conn)
        .optional()?;

    Ok(result)
}

/// Selects the row from the `proposer_info` table where `slot` is maximum.
pub fn get_highest_proposer_info(conn: &mut PgConn) -> Result<Option<WatchProposerInfo>, Error> {
    use self::proposer_info::dsl::*;

    let result = proposer_info
        .order_by(slot.desc())
        .limit(1)
        .first::<WatchProposerInfo>(conn)
        .optional()?;

    Ok(result)
}

/// Selects a single row of the `proposer_info` table corresponding to a given `root_query`.
pub fn get_proposer_info_by_root(
    conn: &mut PgConn,
    root_query: WatchHash,
) -> Result<Option<WatchProposerInfo>, Error> {
    use self::proposer_info::dsl::*;

    let result = proposer_info
        .filter(block_root.eq(root_query))
        .first::<WatchProposerInfo>(conn)
        .optional()?;

    Ok(result)
}

/// Selects a single row of the `proposer_info` table corresponding to a given `slot_query`.
pub fn get_proposer_info_by_slot(
    conn: &mut PgConn,
    slot_query: WatchSlot,
) -> Result<Option<WatchProposerInfo>, Error> {
    use self::proposer_info::dsl::*;

    let result = proposer_info
        .filter(slot.eq(slot_query))
        .first::<WatchProposerInfo>(conn)
        .optional()?;

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

    let result = proposer_info
        .filter(slot.ge(start_slot))
        .filter(slot.le(end_slot))
        .load::<WatchProposerInfo>(conn)
        .optional()?;

    Ok(result)
}

/// Selects the row from the `block_rewards` table where `slot` is minimum.
pub fn get_lowest_block_rewards(conn: &mut PgConn) -> Result<Option<WatchBlockRewards>, Error> {
    use self::block_rewards::dsl::*;

    let result = block_rewards
        .order_by(slot.asc())
        .limit(1)
        .first::<WatchBlockRewards>(conn)
        .optional()?;

    Ok(result)
}

/// Selects the row from the `block_rewards` table where `slot` is maximum.
pub fn get_highest_block_rewards(conn: &mut PgConn) -> Result<Option<WatchBlockRewards>, Error> {
    use self::block_rewards::dsl::*;

    let result = block_rewards
        .order_by(slot.desc())
        .limit(1)
        .first::<WatchBlockRewards>(conn)
        .optional()?;

    Ok(result)
}

/// Selects a single row of the `block_rewards` table corresponding to a given `root_query`.
pub fn get_block_reward_by_root(
    conn: &mut PgConn,
    root_query: WatchHash,
) -> Result<Option<WatchBlockRewards>, Error> {
    use self::block_rewards::dsl::*;

    let result = block_rewards
        .filter(block_root.eq(root_query))
        .first::<WatchBlockRewards>(conn)
        .optional()?;

    Ok(result)
}

/// Selects a single row of the `block_rewards` table corresponding to a given `slot_query`.
pub fn get_block_reward_by_slot(
    conn: &mut PgConn,
    slot_query: WatchSlot,
) -> Result<Option<WatchBlockRewards>, Error> {
    use self::block_rewards::dsl::*;

    let result = block_rewards
        .filter(slot.eq(slot_query))
        .first::<WatchBlockRewards>(conn)
        .optional()?;

    Ok(result)
}

/// Selects `slot` from all rows of the `beacon_blocks` table which do not have a corresponding
/// row in `block_rewards`.
pub fn get_unknown_block_rewards(conn: &mut PgConn) -> Result<Vec<Option<WatchSlot>>, Error> {
    use self::beacon_blocks::dsl::{beacon_blocks, slot};
    use self::block_rewards::dsl::{block_rewards, block_root};

    let join = beacon_blocks.left_join(block_rewards);

    let result = join
        .select(slot)
        .filter(block_root.is_null())
        // Block metadata cannot be retrieved for `slot == 0` so we need to exclude it.
        .filter(slot.ne(0))
        .order_by(slot.desc())
        .nullable()
        .load::<Option<WatchSlot>>(conn)?;

    Ok(result)
}

/// Selects the row from the `block_packing` table where `slot` is minimum.
pub fn get_lowest_block_packing(conn: &mut PgConn) -> Result<Option<WatchBlockPacking>, Error> {
    use self::block_packing::dsl::*;

    let result = block_packing
        .order_by(slot.asc())
        .limit(1)
        .first::<WatchBlockPacking>(conn)
        .optional()?;

    Ok(result)
}

/// Selects the row from the `block_packing` table where `slot` is maximum.
pub fn get_highest_block_packing(conn: &mut PgConn) -> Result<Option<WatchBlockPacking>, Error> {
    use self::block_packing::dsl::*;

    let result = block_packing
        .order_by(slot.desc())
        .limit(1)
        .first::<WatchBlockPacking>(conn)
        .optional()?;

    Ok(result)
}

/// Selects a single row of the `block_packing` table corresponding to a given `root_query`.
pub fn get_block_packing_by_root(
    conn: &mut PgConn,
    root_query: WatchHash,
) -> Result<Option<WatchBlockPacking>, Error> {
    use self::block_packing::dsl::*;

    let result = block_packing
        .filter(block_root.eq(root_query))
        .first::<WatchBlockPacking>(conn)
        .optional()?;

    Ok(result)
}

/// Selects a single row of the `block_packing` table corresponding to a given `slot_query`.
pub fn get_block_packing_by_slot(
    conn: &mut PgConn,
    slot_query: WatchSlot,
) -> Result<Option<WatchBlockPacking>, Error> {
    use self::block_packing::dsl::*;

    let result = block_packing
        .filter(slot.eq(slot_query))
        .first::<WatchBlockPacking>(conn)
        .optional()?;

    Ok(result)
}

/// Selects `slot` from all rows of the `beacon_blocks` table which do not have a corresponding
/// row in `block_packing`.
pub fn get_unknown_block_packing(
    conn: &mut PgConn,
    slots_per_epoch: i32,
) -> Result<Vec<Option<WatchSlot>>, Error> {
    use self::beacon_blocks::dsl::{beacon_blocks, slot as block_slot};
    use self::block_packing::dsl::{block_packing, block_root};

    let join = beacon_blocks.left_join(block_packing);

    let result = join
        .select(block_slot)
        .filter(block_root.is_null())
        // Block packing cannot be retrieved for epoch 0 so we need to exclude them.
        .filter(block_slot.ge(slots_per_epoch))
        .order_by(block_slot.desc())
        .nullable()
        .load::<Option<WatchSlot>>(conn)?;

    Ok(result)
}

///
/// DELETE statements.
///

/// Deletes all rows of the `canonical_slots` table which have `slot` greater than `highest_slot`.
///
/// Due to the ON DELETE CASCADE clause present in the database migration SQL, deleting rows from
/// `canonical_slots` will delete all corresponding rows in `beacon_blocks, `block_rewards`,
/// `block_packing` and `proposer_info`.
pub fn delete_canonical_slots_above(
    conn: &mut PgConn,
    highest_slot: WatchSlot,
) -> Result<usize, Error> {
    use self::canonical_slots::dsl::*;

    let result = diesel::delete(canonical_slots)
        .filter(slot.gt(highest_slot))
        .execute(conn)?;

    debug!(
        "Deleted canonical slots above {}: {} rows deleted",
        highest_slot, result
    );
    Ok(result)
}
