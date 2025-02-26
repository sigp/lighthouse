use crate::database::{
    schema::{beacon_blocks, block_packing},
    watch_types::{WatchHash, WatchSlot},
    Error, PgConn, MAX_SIZE_BATCH_INSERT,
};

use diesel::prelude::*;
use diesel::{Insertable, Queryable};
use log::debug;
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = block_packing)]
pub struct WatchBlockPacking {
    pub slot: WatchSlot,
    pub available: i32,
    pub included: i32,
    pub prior_skip_slots: i32,
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
#[allow(dead_code)]
pub fn get_unknown_block_packing(
    conn: &mut PgConn,
    slots_per_epoch: u64,
) -> Result<Vec<Option<WatchSlot>>, Error> {
    use self::beacon_blocks::dsl::{beacon_blocks, root, slot};
    use self::block_packing::dsl::block_packing;

    let join = beacon_blocks.left_join(block_packing);

    let result = join
        .select(slot)
        .filter(root.is_null())
        // Block packing cannot be retrieved for epoch 0 so we need to exclude them.
        .filter(slot.ge(slots_per_epoch as i32))
        .order_by(slot.desc())
        .nullable()
        .load::<Option<WatchSlot>>(conn)?;

    Ok(result)
}
