use super::{
    ClientDB,
    DBError,
};

mod block_store;
mod pow_chain_store;

pub use self::block_store::BlockStore;
pub use self::pow_chain_store::PoWChainStore;

const BLOCKS_DB_COLUMN: &str = "blocks";
const POW_CHAIN_DB_COLUMN: &str = "powchain";
