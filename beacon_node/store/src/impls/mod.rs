use crate::StoreError as Error;
use ssz::{Decode, Encode};
use types::EthSpec;

pub mod beacon_state;
pub use beacon_state::*; 