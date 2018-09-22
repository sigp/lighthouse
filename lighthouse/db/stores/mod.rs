use super::{
    ClientDB,
    DBError,
};

mod block_store;
mod pow_chain_store;
mod validator_store;

pub use self::block_store::BlockStore;
pub use self::pow_chain_store::PoWChainStore;
pub use self::validator_store::ValidatorStore;

const BLOCKS_DB_COLUMN: &str = "blocks";
const POW_CHAIN_DB_COLUMN: &str = "powchain";
const VALIDATOR_DB_COLUMN: &str = "validator";
