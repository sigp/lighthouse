/*
 * Implementations for various types
 */
use super::{
    DecodeError,
    Decodable,
    Encodable,
    SszStream
};
use super::bytes::{ BytesMut, BufMut };
use super::ethereum_types::{ H256, U256 };

macro_rules! impl_decodable_for_uint {
    ($type: ident, $bit_size: expr) => {
        impl Decodable for $type {
            fn ssz_decode(bytes: &[u8])
                -> Result<Self, DecodeError>
            {
                assert!(0 < $bit_size &&
                       $bit_size <= 64 &&
                       $bit_size % 8 == 0);
                let bytes_required = $bit_size / 8;
                if bytes_required <= bytes.len() {
                    let mut result = 0;
                    for i in 0..bytes.len() {
                        let offset = (bytes.len() - i - 1) * 8;
                        result = (bytes[i] << offset) | result;
                    };
                    Ok(result.into())
                } else {
                    Err(DecodeError::TooLong)
                }
            }
        }
    }
}

impl_decodable_for_uint!(u64, 64 / 8);
impl_decodable_for_uint!(u16, 16 / 8);

impl Encodable for u8 {
    fn ssz_append(&self, s: &mut SszStream) {
        s.buffer.append(&mut vec![*self]);
    }
}

impl Encodable for u16 {
    fn ssz_append(&self, s: &mut SszStream) {
        let mut buf = BytesMut::with_capacity(16/8);
        buf.put_u16_be(*self);
        s.extend_buffer(&buf.to_vec());
    }
}

impl Encodable for u32 {
    fn ssz_append(&self, s: &mut SszStream) {
        let mut buf = BytesMut::with_capacity(32/8);
        buf.put_u32_be(*self);
        s.extend_buffer(&buf.to_vec());
    }
}

impl Encodable for u64 {
    fn ssz_append(&self, s: &mut SszStream) {
        let mut buf = BytesMut::with_capacity(64/8);
        buf.put_u64_be(*self);
        s.extend_buffer(&buf.to_vec());
    }
}

impl Encodable for H256 {
    fn ssz_append(&self, s: &mut SszStream) {
        s.extend_buffer(&self.to_vec());
    }
}

impl Encodable for U256 {
    fn ssz_append(&self, s: &mut SszStream) {
        let mut a = [0; 32];
        self.to_big_endian(&mut a);
        s.append_encoded_array(&mut a);
    }
}
