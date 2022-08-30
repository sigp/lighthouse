use crate::database::{
    self, PgConn, PgPool, WatchAttestation, WatchBeaconBlock, WatchBlockPacking, WatchBlockRewards,
    WatchCanonicalSlot, WatchHash, WatchProposerInfo, WatchSlot, WatchValidator,
};
use crate::server::Error;
use eth2::types::BlockId;
use std::convert::Infallible;
use types::{Epoch, Slot};
use warp::Filter;

pub fn with_db(db_pool: PgPool) -> impl Filter<Extract = (PgPool,), Error = Infallible> + Clone {
    warp::any().map(move || db_pool.clone())
}

pub fn with_slots_per_epoch(
    slots_per_epoch: u64,
) -> impl Filter<Extract = (u64,), Error = Infallible> + Clone {
    warp::any().map(move || slots_per_epoch)
}

pub fn get_slot(conn: &mut PgConn, block_id: BlockId) -> Result<Option<WatchCanonicalSlot>, Error> {
    let slot_opt = match block_id {
        BlockId::Root(root) => {
            database::get_canonical_slot_by_root(conn, WatchHash::from_hash(root))?
        }
        BlockId::Slot(slot) => database::get_canonical_slot(conn, WatchSlot::from_slot(slot))?,
        _ => unimplemented!(),
    };

    Ok(slot_opt)
}

pub fn get_lowest_slot(conn: &mut PgConn) -> Result<Option<Slot>, Error> {
    Ok(database::get_lowest_canonical_slot(conn)?.map(|s| s.slot.as_slot()))
}

pub fn get_highest_slot(conn: &mut PgConn) -> Result<Option<Slot>, Error> {
    Ok(database::get_highest_canonical_slot(conn)?.map(|s| s.slot.as_slot()))
}

pub fn get_block(conn: &mut PgConn, block_id: BlockId) -> Result<Option<WatchBeaconBlock>, Error> {
    let block_opt = match block_id {
        BlockId::Root(root) => {
            database::get_beacon_block_by_root(conn, WatchHash::from_hash(root))?
        }
        BlockId::Slot(slot) => {
            database::get_beacon_block_by_slot(conn, WatchSlot::from_slot(slot))?
        }
        _ => unimplemented!(),
    };

    Ok(block_opt)
}

pub fn get_lowest_beacon_block(conn: &mut PgConn) -> Result<Option<WatchBeaconBlock>, Error> {
    Ok(database::get_lowest_beacon_block(conn)?)
}

pub fn get_highest_beacon_block(conn: &mut PgConn) -> Result<Option<WatchBeaconBlock>, Error> {
    Ok(database::get_highest_beacon_block(conn)?)
}

pub fn get_next_beacon_block(
    conn: &mut PgConn,
    parent: BlockId,
) -> Result<Option<WatchBeaconBlock>, Error> {
    let block = match parent {
        BlockId::Root(root) => {
            database::get_beacon_block_with_parent(conn, WatchHash::from_hash(root))?
        }
        BlockId::Slot(slot) => {
            database::get_beacon_block_by_slot(conn, WatchSlot::from_slot(slot + 1_u64))?
        }
        _ => unimplemented!(),
    };

    Ok(block)
}

pub fn get_validator_by_index(
    conn: &mut PgConn,
    index: i32,
) -> Result<Option<WatchValidator>, Error> {
    Ok(database::get_validator_by_index(conn, index)?)
}

// Will return Ok(None) if the epoch is not synced or if the validator does not exist.
// In the future it might be worth differentiating these events.
pub fn get_validator_attestation(
    conn: &mut PgConn,
    index: i32,
    epoch: Epoch,
    slots_per_epoch: u64,
) -> Result<Option<WatchAttestation>, Error> {
    // Ensure the database has synced the target epoch.
    if database::get_canonical_slot(conn, WatchSlot::from_slot(epoch.end_slot(slots_per_epoch)))?
        .is_none()
    {
        // Epoch is not fully synced.
        return Ok(None);
    }

    let attestation = if let Some(suboptimal_attestation) =
        database::get_attestation(conn, index, epoch, slots_per_epoch)?
    {
        Some(suboptimal_attestation.to_attestation(slots_per_epoch))
    } else {
        // Attestation was not in database. Check if the validator was active.
        match database::get_validator_by_index(conn, index)? {
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
    Ok(attestation)
}

pub fn get_proposer_info(
    conn: &mut PgConn,
    block_id: BlockId,
) -> Result<Option<WatchProposerInfo>, Error> {
    let info = match block_id {
        BlockId::Root(root) => {
            database::get_proposer_info_by_root(conn, WatchHash::from_hash(root))?
        }
        BlockId::Slot(slot) => {
            database::get_proposer_info_by_slot(conn, WatchSlot::from_slot(slot))?
        }
        _ => unimplemented!(),
    };

    Ok(info)
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

pub fn get_block_reward(
    conn: &mut PgConn,
    block_id: BlockId,
) -> Result<Option<WatchBlockRewards>, Error> {
    let reward = match block_id {
        BlockId::Root(root) => {
            database::get_block_reward_by_root(conn, WatchHash::from_hash(root))?
        }
        BlockId::Slot(slot) => {
            database::get_block_reward_by_slot(conn, WatchSlot::from_slot(slot))?
        }
        _ => unimplemented!(),
    };

    Ok(reward)
}

pub fn get_block_packing(
    conn: &mut PgConn,
    block_id: BlockId,
) -> Result<Option<WatchBlockPacking>, Error> {
    let packing = match block_id {
        BlockId::Root(root) => {
            database::get_block_packing_by_root(conn, WatchHash::from_hash(root))?
        }
        BlockId::Slot(slot) => {
            database::get_block_packing_by_slot(conn, WatchSlot::from_slot(slot))?
        }
        _ => unimplemented!(),
    };

    Ok(packing)
}
