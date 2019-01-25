/*
 * This is a WIP of implementing an alternative
 * serialization strategy. It attempts to follow Vitalik's
 * "simpleserialize" format here:
 * https://github.com/ethereum/beacon_chain/blob/master/beacon_chain/utils/simpleserialize.py
 *
 * This implementation is not final and would almost certainly
 * have issues.
 */
extern crate bytes;
extern crate ethereum_types;

pub mod decode;
pub mod encode;
pub mod tree_hash;

mod impl_decode;
mod impl_encode;
mod impl_tree_hash;

pub use crate::decode::{decode_ssz, decode_ssz_list, Decodable, DecodeError};
pub use crate::encode::{Encodable, SszStream};
pub use crate::tree_hash::{merkle_hash, TreeHash};

pub const LENGTH_BYTES: usize = 4;
pub const MAX_LIST_SIZE: usize = 1 << (4 * 8);

/// Convenience function to SSZ encode an object supporting ssz::Encode.
pub fn ssz_encode<T>(val: &T) -> Vec<u8>
where
    T: Encodable,
{
    let mut ssz_stream = SszStream::new();
    ssz_stream.append(val);
    ssz_stream.drain()
}
