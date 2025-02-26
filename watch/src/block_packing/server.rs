use crate::block_packing::database::{
    get_block_packing_by_root, get_block_packing_by_slot, WatchBlockPacking,
};
use crate::database::{get_connection, PgPool, WatchHash, WatchSlot};
use crate::server::Error;

use axum::{extract::Path, routing::get, Extension, Json, Router};
use eth2::types::BlockId;
use std::str::FromStr;

pub async fn get_block_packing(
    Path(block_query): Path<String>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchBlockPacking>>, Error> {
    let mut conn = get_connection(&pool).map_err(Error::Database)?;
    match BlockId::from_str(&block_query).map_err(|_| Error::BadRequest)? {
        BlockId::Root(root) => Ok(Json(get_block_packing_by_root(
            &mut conn,
            WatchHash::from_hash(root),
        )?)),
        BlockId::Slot(slot) => Ok(Json(get_block_packing_by_slot(
            &mut conn,
            WatchSlot::from_slot(slot),
        )?)),
        _ => Err(Error::BadRequest),
    }
}

pub fn block_packing_routes() -> Router {
    Router::new().route("/v1/blocks/:block/packing", get(get_block_packing))
}
