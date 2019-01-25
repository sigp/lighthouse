mod beacon_block;
mod beacon_state;

pub use crate::beacon_block::genesis_beacon_block;
pub use crate::beacon_state::{genesis_beacon_state, Error as GenesisError};
