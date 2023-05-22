use crate::database::{
    self,
    schema::{beacon_blocks, blockprint},
    watch_types::{WatchHash, WatchSlot},
    Error, PgConn, MAX_SIZE_BATCH_INSERT,
};

use diesel::prelude::*;
use diesel::sql_types::{Integer, Text};
use diesel::{Insertable, Queryable};
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

type WatchConsensusClient = String;
pub fn list_consensus_clients() -> Vec<WatchConsensusClient> {
    vec![
        "Lighthouse".to_string(),
        "Lodestar".to_string(),
        "Nimbus".to_string(),
        "Prysm".to_string(),
        "Teku".to_string(),
        "Unknown".to_string(),
    ]
}

#[derive(Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = blockprint)]
pub struct WatchBlockprint {
    pub slot: WatchSlot,
    pub best_guess: WatchConsensusClient,
}

#[derive(Debug, QueryableByName, diesel::FromSqlRow)]
pub struct WatchValidatorBlockprint {
    #[diesel(sql_type = Integer)]
    pub proposer_index: i32,
    #[diesel(sql_type = Text)]
    pub best_guess: WatchConsensusClient,
    #[diesel(sql_type = Integer)]
    pub slot: WatchSlot,
}

/// Insert a batch of values into the `blockprint` table.
///
/// On a conflict, it will do nothing, leaving the old value.
pub fn insert_batch_blockprint(
    conn: &mut PgConn,
    prints: Vec<WatchBlockprint>,
) -> Result<(), Error> {
    use self::blockprint::dsl::*;

    let mut count = 0;
    let timer = Instant::now();

    for chunk in prints.chunks(MAX_SIZE_BATCH_INSERT) {
        count += diesel::insert_into(blockprint)
            .values(chunk)
            .on_conflict_do_nothing()
            .execute(conn)?;
    }

    let time_taken = timer.elapsed();
    debug!("Blockprint inserted, count: {count}, time_taken: {time_taken:?}");
    Ok(())
}

/// Selects the row from the `blockprint` table where `slot` is minimum.
pub fn get_lowest_blockprint(conn: &mut PgConn) -> Result<Option<WatchBlockprint>, Error> {
    use self::blockprint::dsl::*;
    let timer = Instant::now();

    let result = blockprint
        .order_by(slot.asc())
        .limit(1)
        .first::<WatchBlockprint>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Blockprint requested: lowest, time_taken: {time_taken:?}");
    Ok(result)
}

/// Selects the row from the `blockprint` table where `slot` is maximum.
pub fn get_highest_blockprint(conn: &mut PgConn) -> Result<Option<WatchBlockprint>, Error> {
    use self::blockprint::dsl::*;
    let timer = Instant::now();

    let result = blockprint
        .order_by(slot.desc())
        .limit(1)
        .first::<WatchBlockprint>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Blockprint requested: highest, time_taken: {time_taken:?}");
    Ok(result)
}

/// Selects a single row of the `blockprint` table corresponding to a given `root_query`.
pub fn get_blockprint_by_root(
    conn: &mut PgConn,
    root_query: WatchHash,
) -> Result<Option<WatchBlockprint>, Error> {
    use self::beacon_blocks::dsl::{beacon_blocks, root};
    use self::blockprint::dsl::*;
    let timer = Instant::now();

    let join = beacon_blocks.inner_join(blockprint);

    let result = join
        .select((slot, best_guess))
        .filter(root.eq(root_query))
        .first::<WatchBlockprint>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Blockprint requested: {root_query}, time_taken: {time_taken:?}");
    Ok(result)
}

/// Selects a single row of the `blockprint` table corresponding to a given `slot_query`.
pub fn get_blockprint_by_slot(
    conn: &mut PgConn,
    slot_query: WatchSlot,
) -> Result<Option<WatchBlockprint>, Error> {
    use self::blockprint::dsl::*;
    let timer = Instant::now();

    let result = blockprint
        .filter(slot.eq(slot_query))
        .first::<WatchBlockprint>(conn)
        .optional()?;

    let time_taken = timer.elapsed();
    debug!("Blockprint requested: {slot_query}, time_taken: {time_taken:?}");
    Ok(result)
}

/// Selects `slot` from all rows of the `beacon_blocks` table which do not have a corresponding
/// row in `blockprint`.
#[allow(dead_code)]
pub fn get_unknown_blockprint(conn: &mut PgConn) -> Result<Vec<Option<WatchSlot>>, Error> {
    use self::beacon_blocks::dsl::{beacon_blocks, root, slot};
    use self::blockprint::dsl::blockprint;

    let join = beacon_blocks.left_join(blockprint);

    let result = join
        .select(slot)
        .filter(root.is_null())
        .order_by(slot.desc())
        .nullable()
        .load::<Option<WatchSlot>>(conn)?;

    Ok(result)
}

/// Constructs a HashMap of `index` -> `best_guess` for each validator's latest proposal at or before
/// `target_slot`.
/// Inserts `"Unknown" if no prior proposals exist.
pub fn construct_validator_blockprints_at_slot(
    conn: &mut PgConn,
    target_slot: WatchSlot,
    slots_per_epoch: u64,
) -> Result<HashMap<i32, WatchConsensusClient>, Error> {
    use self::blockprint::dsl::{blockprint, slot};

    let total_validators =
        database::count_validators_activated_before_slot(conn, target_slot, slots_per_epoch)?
            as usize;

    let mut blockprint_map = HashMap::with_capacity(total_validators);

    let latest_proposals =
        database::get_all_validators_latest_proposer_info_at_slot(conn, target_slot)?;

    let latest_proposal_slots: Vec<WatchSlot> = latest_proposals.clone().into_keys().collect();

    let result = blockprint
        .filter(slot.eq_any(latest_proposal_slots))
        .load::<WatchBlockprint>(conn)?;

    // Insert the validators which have available blockprints.
    for print in result {
        if let Some(proposer) = latest_proposals.get(&print.slot) {
            blockprint_map.insert(*proposer, print.best_guess);
        }
    }

    // Insert the rest of the unknown validators.
    for validator_index in 0..total_validators {
        blockprint_map
            .entry(validator_index as i32)
            .or_insert_with(|| "Unknown".to_string());
    }

    Ok(blockprint_map)
}

/// Counts the number of occurances of each `client` present in the `validators` table at or before some
/// `target_slot`.
pub fn get_validators_clients_at_slot(
    conn: &mut PgConn,
    target_slot: WatchSlot,
    slots_per_epoch: u64,
) -> Result<HashMap<WatchConsensusClient, usize>, Error> {
    let mut client_map: HashMap<WatchConsensusClient, usize> = HashMap::new();

    // This includes all validators which were activated at or before `target_slot`.
    let validator_blockprints =
        construct_validator_blockprints_at_slot(conn, target_slot, slots_per_epoch)?;

    for client in list_consensus_clients() {
        let count = validator_blockprints
            .iter()
            .filter(|(_, v)| (*v).clone() == client)
            .count();
        client_map.insert(client, count);
    }

    Ok(client_map)
}
