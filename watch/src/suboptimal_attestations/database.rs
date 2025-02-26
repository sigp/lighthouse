use crate::database::{
    schema::{suboptimal_attestations, validators},
    watch_types::{WatchPK, WatchSlot},
    Error, PgConn, MAX_SIZE_BATCH_INSERT,
};

use diesel::prelude::*;
use diesel::{Insertable, Queryable};
use log::debug;
use serde::{Deserialize, Serialize};
use std::time::Instant;

use types::Epoch;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct WatchAttestation {
    pub index: i32,
    pub epoch: Epoch,
    pub source: bool,
    pub head: bool,
    pub target: bool,
}

impl WatchAttestation {
    pub fn optimal(index: i32, epoch: Epoch) -> WatchAttestation {
        WatchAttestation {
            index,
            epoch,
            source: true,
            head: true,
            target: true,
        }
    }
}

#[derive(Debug, Queryable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = suboptimal_attestations)]
pub struct WatchSuboptimalAttestation {
    pub epoch_start_slot: WatchSlot,
    pub index: i32,
    pub source: bool,
    pub head: bool,
    pub target: bool,
}

impl WatchSuboptimalAttestation {
    pub fn to_attestation(&self, slots_per_epoch: u64) -> WatchAttestation {
        WatchAttestation {
            index: self.index,
            epoch: self.epoch_start_slot.epoch(slots_per_epoch),
            source: self.source,
            head: self.head,
            target: self.target,
        }
    }
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

/// Selects a single row from the `suboptimal_attestations` table corresponding
/// to a given `pubkey_query` and `epoch_query`.
#[allow(dead_code)]
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

/// Selects `index` for all validators in the suboptimal_attestations table
/// that have `source == false` for the corresponding `epoch_start_slot_query`.
pub fn get_validators_missed_source(
    conn: &mut PgConn,
    epoch_start_slot_query: WatchSlot,
) -> Result<Vec<i32>, Error> {
    use self::suboptimal_attestations::dsl::*;

    Ok(suboptimal_attestations
        .select(index)
        .filter(epoch_start_slot.eq(epoch_start_slot_query))
        .filter(source.eq(false))
        .load::<i32>(conn)?)
}

/// Selects `index` for all validators in the suboptimal_attestations table
/// that have `head == false` for the corresponding `epoch_start_slot_query`.
pub fn get_validators_missed_head(
    conn: &mut PgConn,
    epoch_start_slot_query: WatchSlot,
) -> Result<Vec<i32>, Error> {
    use self::suboptimal_attestations::dsl::*;

    Ok(suboptimal_attestations
        .select(index)
        .filter(epoch_start_slot.eq(epoch_start_slot_query))
        .filter(head.eq(false))
        .load::<i32>(conn)?)
}

/// Selects `index` for all validators in the suboptimal_attestations table
/// that have `target == false` for the corresponding `epoch_start_slot_query`.
pub fn get_validators_missed_target(
    conn: &mut PgConn,
    epoch_start_slot_query: WatchSlot,
) -> Result<Vec<i32>, Error> {
    use self::suboptimal_attestations::dsl::*;

    Ok(suboptimal_attestations
        .select(index)
        .filter(epoch_start_slot.eq(epoch_start_slot_query))
        .filter(target.eq(false))
        .load::<i32>(conn)?)
}

/// Selects all rows from the `suboptimal_attestations` table for the given
/// `epoch_start_slot_query`.
pub fn get_all_suboptimal_attestations_for_epoch(
    conn: &mut PgConn,
    epoch_start_slot_query: WatchSlot,
) -> Result<Vec<WatchSuboptimalAttestation>, Error> {
    use self::suboptimal_attestations::dsl::*;

    Ok(suboptimal_attestations
        .filter(epoch_start_slot.eq(epoch_start_slot_query))
        .load::<WatchSuboptimalAttestation>(conn)?)
}
