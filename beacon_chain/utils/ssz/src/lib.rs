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

mod encode;
mod impl_encode;
mod impl_decode;

pub use decode::{
    Decodable,
    DecodeError,
    decode_ssz,
    decode_ssz_list,
};
pub use encode::{
    Encodable,
    SszStream,
};

pub const LENGTH_BYTES: usize = 4;
pub const MAX_LIST_SIZE : usize = 1 << (4 * 8);
