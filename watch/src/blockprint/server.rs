use crate::blockprint::database::{
    get_blockprint_by_root, get_blockprint_by_slot, WatchBlockprint,
};
use crate::database::{get_connection, PgPool, WatchHash, WatchSlot};
use crate::server::Error;

use axum::{extract::Path, routing::get, Extension, Json, Router};
use eth2::types::BlockId;
use std::str::FromStr;

pub async fn get_blockprint(
    Path(block_query): Path<String>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Option<WatchBlockprint>>, Error> {
    let mut conn = get_connection(&pool).map_err(Error::Database)?;
    match BlockId::from_str(&block_query).map_err(|_| Error::BadRequest)? {
        BlockId::Root(root) => Ok(Json(get_blockprint_by_root(
            &mut conn,
            WatchHash::from_hash(root),
        )?)),
        BlockId::Slot(slot) => Ok(Json(get_blockprint_by_slot(
            &mut conn,
            WatchSlot::from_slot(slot),
        )?)),
        _ => Err(Error::BadRequest),
    }
}

pub fn blockprint_routes() -> Router {
    Router::new().route("/v1/blocks/:block/blockprint", get(get_blockprint))
    //.route("/v1/blockprint/test/:slot", get(get_all_validators))
}
