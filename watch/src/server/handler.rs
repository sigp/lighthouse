use super::Error;
use crate::{database::WatchBeaconBlock, Config, Database};
use eth2::types::BlockId;
use std::future::Future;

pub async fn get_db(config: &Config) -> Result<Database, Error> {
    Database::connect(&config).await.map_err(Into::into)
}

pub async fn with_db<F, R, T>(config: &Config, func: F) -> Result<T, Error>
where
    F: Fn(Database) -> R,
    R: Future<Output = Result<T, Error>>,
{
    let mut db = get_db(config).await?;
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
