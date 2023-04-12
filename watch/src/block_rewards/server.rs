use crate::block_rewards::database::{
    get_block_rewards_by_root, get_block_rewards_by_slot, WatchBlockRewards,
};
use crate::database::{get_connection, PgPool, WatchHash, WatchSlot};
use crate::server::Error;

use axum::{extract::Path, routing::get, Extension, Json, Router};
use eth2::types::BlockId;
use std::str::FromStr;

pub async fn get_block_rewards(
    Path(block_query): Path<String>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchBlockRewards>>, Error> {
    let mut conn = get_connection(&pool).map_err(Error::Database)?;
    match BlockId::from_str(&block_query).map_err(|_| Error::BadRequest)? {
        BlockId::Root(root) => Ok(Json(get_block_rewards_by_root(
            &mut conn,
            WatchHash::from_hash(root),
        )?)),
        BlockId::Slot(slot) => Ok(Json(get_block_rewards_by_slot(
            &mut conn,
            WatchSlot::from_slot(slot),
        )?)),
        _ => Err(Error::BadRequest),
    }
}

pub fn block_rewards_routes() -> Router {
    Router::new().route("/v1/blocks/:block/rewards", get(get_block_rewards))
}
