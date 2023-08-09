use crate::database::{
    schema::{beacon_blocks, block_rewards},
    watch_types::{WatchHash, WatchSlot},
    Error, PgConn, MAX_SIZE_BATCH_INSERT,
};

use diesel::prelude::*;
use diesel::{Insertable, Queryable};
use log::debug;
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = block_rewards)]
pub struct WatchBlockRewards {
    pub slot: WatchSlot,
    pub total: i32,
    pub attestation_reward: i32,
    pub sync_committee_reward: i32,
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
pub fn get_block_rewards_by_root(
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
pub fn get_block_rewards_by_slot(
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
#[allow(dead_code)]
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
