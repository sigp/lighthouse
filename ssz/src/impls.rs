/*
 * Implementations for various types
 */
use super::{ Encodable, SszStream };
use super::bytes::{ BytesMut, BufMut };
use super::ethereum_types::{ H256, U256 };

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
