use crate::database::{
    self, PgConn, PgPool, WatchBeaconBlock, WatchBlockPacking, WatchBlockRewards, WatchHash,
    WatchProposerInfo, WatchSlot,
};
use crate::server::Error;
use eth2::types::BlockId;
use std::convert::Infallible;
use types::{Epoch, Slot};
use warp::Filter;

pub fn with_db(db_pool: PgPool) -> impl Filter<Extract = (PgPool,), Error = Infallible> + Clone {
    warp::any().map(move || db_pool.clone())
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
