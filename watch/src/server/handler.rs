use crate::database::{
    self, PgConn, PgPool, WatchAttestation, WatchBeaconBlock, WatchBlockPacking, WatchBlockRewards,
    WatchCanonicalSlot, WatchHash, WatchPK, WatchProposerInfo, WatchSlot, WatchValidator,
};
use crate::server::Error;
use axum::{
    extract::{Path, Query},
    Extension, Json,
};
use eth2::types::BlockId;
use std::collections::HashMap;
use std::str::FromStr;
use types::Epoch;

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

pub async fn get_block_reward(
    Path(block_query): Path<String>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchBlockRewards>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    match BlockId::from_str(&block_query).map_err(|_| Error::BadRequest)? {
        BlockId::Root(root) => Ok(Json(database::get_block_reward_by_root(
            &mut conn,
            WatchHash::from_hash(root),
        )?)),
        BlockId::Slot(slot) => Ok(Json(database::get_block_reward_by_slot(
            &mut conn,
            WatchSlot::from_slot(slot),
        )?)),
        _ => Err(Error::BadRequest),
    }
}

pub async fn get_block_packing(
    Path(block_query): Path<String>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchBlockPacking>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    match BlockId::from_str(&block_query).map_err(|_| Error::BadRequest)? {
        BlockId::Root(root) => Ok(Json(database::get_block_packing_by_root(
            &mut conn,
            WatchHash::from_hash(root),
        )?)),
        BlockId::Slot(slot) => Ok(Json(database::get_block_packing_by_slot(
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

// Will return Ok(None) if the epoch is not synced or if the validator does not exist.
// In the future it might be worth differentiating these events.
pub async fn get_validator_attestation(
    Path((validator_query, epoch_query)): Path<(String, u64)>,
    Extension(pool): Extension<PgPool>,
    Extension(slots_per_epoch): Extension<u64>,
) -> Result<Json<Option<WatchAttestation>>, Error> {
    let mut conn = database::get_connection(&pool).map_err(Error::Database)?;
    let epoch = Epoch::new(epoch_query);

    // Ensure the database has synced the target epoch.
    if database::get_canonical_slot(
        &mut conn,
        WatchSlot::from_slot(epoch.end_slot(slots_per_epoch)),
    )?
    .is_none()
    {
        // Epoch is not fully synced.
        return Ok(Json(None));
    }

    let index = if validator_query.starts_with("0x") {
        let pubkey = WatchPK::from_str(&validator_query).map_err(|_| Error::BadRequest)?;
        database::get_validator_by_public_key(&mut conn, pubkey)?
            .ok_or(Error::NotFound)?
            .index
    } else {
        i32::from_str(&validator_query).map_err(|_| Error::BadRequest)?
    };
    let attestation = if let Some(suboptimal_attestation) =
        database::get_attestation_by_index(&mut conn, index, epoch, slots_per_epoch)?
    {
        Some(suboptimal_attestation.to_attestation(slots_per_epoch))
    } else {
        // Attestation was not in database. Check if the validator was active.
        match database::get_validator_by_index(&mut conn, index)? {
            Some(validator) => {
                if let Some(activation_epoch) = validator.activation_epoch {
                    if activation_epoch <= epoch.as_u64() as i32 {
                        if let Some(exit_epoch) = validator.exit_epoch {
                            if exit_epoch > epoch.as_u64() as i32 {
                                // Validator is active and has not yet exited.
                                Some(WatchAttestation::optimal(index, epoch))
                            } else {
                                // Validator has exited.
                                None
                            }
                        } else {
                            // Validator is active and has not yet exited.
                            Some(WatchAttestation::optimal(index, epoch))
                        }
                    } else {
                        // Validator is not yet active.
                        None
                    }
                } else {
                    // Validator is not yet active.
                    None
                }
            }
            None => return Err(Error::Other("Validator index does not exist".to_string())),
        }
    };
    Ok(Json(attestation))
}

#[allow(dead_code)]
pub fn get_proposer_info_by_range(
    conn: &mut PgConn,
    start_epoch: Epoch,
    end_epoch: Epoch,
    slots_per_epoch: u64,
) -> Result<Option<Vec<WatchProposerInfo>>, Error> {
    let start_slot = WatchSlot::from_slot(start_epoch.start_slot(slots_per_epoch));
    let end_slot = WatchSlot::from_slot(end_epoch.end_slot(slots_per_epoch));

    let result = database::get_proposer_info_by_range(conn, start_slot, end_slot)?;

    Ok(result)
}
