use ethereum_types::{Address, H256};
use ssz::{ssz_encode, Decodable, DecodeError, Encodable, SszStream};

/// Convenience function to encode an object.
pub fn db_encode<T>(val: &T) -> Vec<u8>
where
    T: DBEncode,
{
    let mut ssz_stream = SszStream::new();
    ssz_stream.append(val);
    ssz_stream.drain()
}

/// An encoding scheme based solely upon SSZ.
///
/// The reason we have a separate encoding scheme is to allows us to store fields in the DB that we
/// don't want to transmit across the wire or hash.
///
/// For example, the cache fields on `BeaconState` should be stored in the DB, but they should not
/// be hashed or transmitted across the wire. `DBEncode` allows us to define two serialization
/// methods, one that encodes the caches and one that does not.
pub trait DBEncode: Encodable + Sized {
    fn db_encode(&self, s: &mut SszStream) {
        s.append(&ssz_encode(self));
    }
}

/// A decoding scheme based solely upon SSZ.
///
/// See `DBEncode` for reasoning on why this trait exists.
pub trait DBDecode: Decodable {
    fn db_decode(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
        Self::ssz_decode(bytes, index)
    }
}

// Implement encoding.
impl DBEncode for bool {}
impl DBEncode for u8 {}
impl DBEncode for u16 {}
impl DBEncode for u32 {}
impl DBEncode for u64 {}
impl DBEncode for usize {}
impl<T> DBEncode for Vec<T> where T: Encodable + Sized {}

impl DBEncode for H256 {}
impl DBEncode for Address {}

// Implement decoding.
impl DBDecode for bool {}
impl DBDecode for u8 {}
impl DBDecode for u16 {}
impl DBDecode for u32 {}
impl DBDecode for u64 {}
impl DBDecode for usize {}
impl<T> DBDecode for Vec<T> where T: Decodable {}

impl DBDecode for H256 {}
impl DBDecode for Address {}
