use super::ethereum_types::{ H256, H160 };

pub use super::blake2::Blake2s;

// TODO: presently the compiler accepts these two types
// as interchangable. This is somewhat loose typing, 
// which is bad. Make the compiler think they're incompatible.
pub type Sha256Digest = H256;
pub type Blake2sDigest = H256;

pub type Address = H160;

pub type StateHash = [u8; 64];

pub type Bitfield = Vec<u8>;
