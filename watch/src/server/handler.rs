use crate::database::{
    self, Error as DbError, PgPool, WatchBeaconBlock, WatchCanonicalSlot, WatchHash, WatchPK,
    WatchProposerInfo, WatchSlot, WatchValidator,
};
use crate::server::Error;
use axum::{
    extract::{Path, Query},
    Extension, Json,
};
use eth2::types::BlockId;
use std::collections::HashMap;
use std::str::FromStr;

pub async fn get_slot(
    Path(slot): Path<u64>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchCanonicalSlot>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    Ok(Json(database::get_canonical_slot(
        &mut conn,
        WatchSlot::new(slot),
    )?))
}

pub async fn get_slot_lowest(
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchCanonicalSlot>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    Ok(Json(database::get_lowest_canonical_slot(&mut conn)?))
}

pub async fn get_slot_highest(
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchCanonicalSlot>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    Ok(Json(database::get_highest_canonical_slot(&mut conn)?))
}

pub async fn get_slots_by_range(
    Query(query): Query<HashMap<String, u64>>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<Vec<WatchCanonicalSlot>>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    if let Some(start_slot) = query.get("start_slot") {
        if let Some(end_slot) = query.get("end_slot") {
            if start_slot > end_slot {
                Err(Error::BadRequest)
            } else {
                Ok(Json(database::get_canonical_slots_by_range(
                    &mut conn,
                    WatchSlot::new(*start_slot),
                    WatchSlot::new(*end_slot),
                )?))
            }
        } else {
            Err(Error::BadRequest)
        }
    } else {
        Err(Error::BadRequest)
    }
}

pub async fn get_block(
    Path(block_query): Path<String>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchBeaconBlock>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    let block_id: BlockId = BlockId::from_str(&block_query).map_err(|_| Error::BadRequest)?;
    match block_id {
        BlockId::Slot(slot) => Ok(Json(database::get_beacon_block_by_slot(
            &mut conn,
            WatchSlot::from_slot(slot),
        )?)),
        BlockId::Root(root) => Ok(Json(database::get_beacon_block_by_root(
            &mut conn,
            WatchHash::from_hash(root),
        )?)),
        _ => Err(Error::BadRequest),
    }
}

pub async fn get_block_lowest(
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchBeaconBlock>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    Ok(Json(database::get_lowest_beacon_block(&mut conn)?))
}

pub async fn get_block_highest(
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchBeaconBlock>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    Ok(Json(database::get_highest_beacon_block(&mut conn)?))
}

pub async fn get_block_previous(
    Path(block_query): Path<String>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchBeaconBlock>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    match BlockId::from_str(&block_query).map_err(|_| Error::BadRequest)? {
        BlockId::Root(root) => {
            if let Some(block) =
                database::get_beacon_block_by_root(&mut conn, WatchHash::from_hash(root))?
                    .map(|block| block.parent_root)
            {
                Ok(Json(database::get_beacon_block_by_root(&mut conn, block)?))
            } else {
                Err(Error::NotFound)
            }
        }
        BlockId::Slot(slot) => Ok(Json(database::get_beacon_block_by_slot(
            &mut conn,
            WatchSlot::new(slot.as_u64().checked_sub(1_u64).ok_or(Error::NotFound)?),
        )?)),
        _ => Err(Error::BadRequest),
    }
}

pub async fn get_block_next(
    Path(block_query): Path<String>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchBeaconBlock>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    match BlockId::from_str(&block_query).map_err(|_| Error::BadRequest)? {
        BlockId::Root(root) => Ok(Json(database::get_beacon_block_with_parent(
            &mut conn,
            WatchHash::from_hash(root),
        )?)),
        BlockId::Slot(slot) => Ok(Json(database::get_beacon_block_by_slot(
            &mut conn,
            WatchSlot::from_slot(slot + 1_u64),
        )?)),
        _ => Err(Error::BadRequest),
    }
}

pub async fn get_blocks_by_range(
    Query(query): Query<HashMap<String, u64>>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<Vec<WatchBeaconBlock>>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    if let Some(start_slot) = query.get("start_slot") {
        if let Some(end_slot) = query.get("end_slot") {
            if start_slot > end_slot {
                Err(Error::BadRequest)
            } else {
                Ok(Json(database::get_beacon_blocks_by_range(
                    &mut conn,
                    WatchSlot::new(*start_slot),
                    WatchSlot::new(*end_slot),
                )?))
            }
        } else {
            Err(Error::BadRequest)
        }
    } else {
        Err(Error::BadRequest)
    }
}

pub async fn get_block_proposer(
    Path(block_query): Path<String>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchProposerInfo>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    match BlockId::from_str(&block_query).map_err(|_| Error::BadRequest)? {
        BlockId::Root(root) => Ok(Json(database::get_proposer_info_by_root(
            &mut conn,
            WatchHash::from_hash(root),
        )?)),
        BlockId::Slot(slot) => Ok(Json(database::get_proposer_info_by_slot(
            &mut conn,
            WatchSlot::from_slot(slot),
        )?)),
        _ => Err(Error::BadRequest),
    }
}

pub async fn get_validator(
    Path(validator_query): Path<String>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchValidator>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    if validator_query.starts_with("0x") {
        let pubkey = WatchPK::from_str(&validator_query).map_err(|_| Error::BadRequest)?;
        Ok(Json(database::get_validator_by_public_key(
            &mut conn, pubkey,
        )?))
    } else {
        let index = i32::from_str(&validator_query).map_err(|_| Error::BadRequest)?;
        Ok(Json(database::get_validator_by_index(&mut conn, index)?))
    }
}

pub async fn get_all_validators(
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Vec<WatchValidator>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    Ok(Json(database::get_all_validators(&mut conn)?))
}

pub async fn get_validator_latest_proposal(
    Path(validator_query): Path<String>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<HashMap<i32, WatchProposerInfo>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    if validator_query.starts_with("0x") {
        let pubkey = WatchPK::from_str(&validator_query).map_err(|_| Error::BadRequest)?;
        let validator =
            database::get_validator_by_public_key(&mut conn, pubkey)?.ok_or(Error::NotFound)?;
        Ok(Json(database::get_validators_latest_proposer_info(
            &mut conn,
            vec![validator.index],
        )?))
    } else {
        let index = i32::from_str(&validator_query).map_err(|_| Error::BadRequest)?;
        Ok(Json(database::get_validators_latest_proposer_info(
            &mut conn,
            vec![index],
        )?))
    }
}

pub async fn get_client_breakdown(
    Extension(pool): Extension<PgPool>,
    Extension(slots_per_epoch): Extension<u64>,
) -> Result<Json<HashMap<String, usize>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;

    if let Some(target_slot) = database::get_highest_canonical_slot(&mut conn)? {
        Ok(Json(database::get_validators_clients_at_slot(
            &mut conn,
            target_slot.slot,
            slots_per_epoch,
        )?))
    } else {
        Err(Error::Database(DbError::Other(
            "No slots found in database.".to_string(),
        )))
    }
}

pub async fn get_client_breakdown_percentages(
    Extension(pool): Extension<PgPool>,
    Extension(slots_per_epoch): Extension<u64>,
) -> Result<Json<HashMap<String, f64>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;

    let mut result = HashMap::new();
    if let Some(target_slot) = database::get_highest_canonical_slot(&mut conn)? {
        let total = database::count_validators_activated_before_slot(
            &mut conn,
            target_slot.slot,
            slots_per_epoch,
        )?;
        let clients =
            database::get_validators_clients_at_slot(&mut conn, target_slot.slot, slots_per_epoch)?;
        for (client, number) in clients.iter() {
            let percentage: f64 = *number as f64 / total as f64 * 100.0;
            result.insert(client.to_string(), percentage);
        }
    }

    Ok(Json(result))
}
