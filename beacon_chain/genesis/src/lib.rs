extern crate spec;
extern crate types;
extern crate validator_induction;
extern crate validator_shuffling;

mod beacon_block;
mod beacon_state;

pub use crate::beacon_block::genesis_beacon_block;
pub use crate::beacon_state::{genesis_beacon_state, Error as GenesisError};
