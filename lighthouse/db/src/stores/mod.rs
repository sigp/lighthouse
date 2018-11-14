use super::{ClientDB, DBError};

mod beacon_block_store;
mod pow_chain_store;
mod validator_store;

pub use self::beacon_block_store::{BeaconBlockAtSlotError, BeaconBlockStore};
pub use self::pow_chain_store::PoWChainStore;
pub use self::validator_store::{ValidatorStore, ValidatorStoreError};

use super::bls;

pub const BLOCKS_DB_COLUMN: &str = "blocks";
pub const POW_CHAIN_DB_COLUMN: &str = "powchain";
pub const VALIDATOR_DB_COLUMN: &str = "validator";

pub const COLUMNS: [&str; 3] = [BLOCKS_DB_COLUMN, POW_CHAIN_DB_COLUMN, VALIDATOR_DB_COLUMN];
