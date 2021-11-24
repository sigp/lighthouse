use super::Error;
use crate::database::{Config, Database, WatchBeaconBlock};
use eth2::types::BlockId;
use std::future::Future;
use types::Slot;

pub async fn get_db(config: &Config) -> Result<Database, Error> {
    Database::connect(&config).await.map_err(Into::into)
}

pub async fn with_db<F, R, T>(config: &Config, func: F) -> Result<T, Error>
where
    F: Fn(Database) -> R,
    R: Future<Output = Result<T, Error>>,
{
    let db = get_db(config).await?;
    func(db).await
}

pub async fn get_block(
    db: &mut Database,
    block_id: BlockId,
) -> Result<Option<WatchBeaconBlock>, Error> {
    // TODO(remove tx)
    let tx = db.transaction().await?;

    let block_opt = match block_id {
        BlockId::Root(root) => Database::get_beacon_block(&tx, root).await?,
        _ => unimplemented!(),
    };

    Ok(block_opt)
}

pub async fn get_lowest_slot(db: &mut Database) -> Result<Option<Slot>, Error> {
    // TODO(remove tx)
    let tx = db.transaction().await?;

    Database::lowest_canonical_slot(&tx)
        .await
        .map_err(Into::into)
}
