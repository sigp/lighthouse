extern crate boolean_bitfield;

use super::ethereum_types::{ H256, H160 };
use self::boolean_bitfield::BooleanBitfield;

pub use super::ethereum_types::U256;

pub type Hash256 = H256;

pub type Address = H160;

pub type Bitfield = BooleanBitfield;
