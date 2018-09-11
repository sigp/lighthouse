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
                assert!((0 < $bit_size) &
                        ($bit_size <= 64) &
                        ($bit_size % 8 == 0));
                let max_bytes = $bit_size / 8;
                if bytes.len() <= max_bytes {
                    let mut result: $type = 0;
                    for i in 0..bytes.len() {
                        let offset = (bytes.len() - i - 1) * 8;
                        result = ((bytes[i] as $type) << offset) | result;
                    };
                    Ok(result)
                } else {
                    Err(DecodeError::TooLong)
                }
            }
        }
    }
}

impl_decodable_for_uint!(u16, 16);
impl_decodable_for_uint!(u32, 32);
impl_decodable_for_uint!(u64, 64);
impl_decodable_for_uint!(usize, 64);

impl Encodable for u8 {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_encoded_val(&mut vec![*self]);
    }
}

impl Encodable for u16 {
    fn ssz_append(&self, s: &mut SszStream) {
        let mut buf = BytesMut::with_capacity(16/8);
        buf.put_u16_be(*self);
        s.append_encoded_val(&buf.to_vec());
    }
}

impl Encodable for u32 {
    fn ssz_append(&self, s: &mut SszStream) {
        let mut buf = BytesMut::with_capacity(32/8);
        buf.put_u32_be(*self);
        s.append_encoded_val(&buf.to_vec());
    }
}

impl Encodable for u64 {
    fn ssz_append(&self, s: &mut SszStream) {
        let mut buf = BytesMut::with_capacity(64/8);
        buf.put_u64_be(*self);
        s.append_encoded_val(&buf.to_vec());
    }
}

impl Encodable for H256 {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_encoded_val(&self.to_vec());
    }
}

impl Encodable for U256 {
    fn ssz_append(&self, s: &mut SszStream) {
        let mut a = [0; 32];
        self.to_big_endian(&mut a);
        s.append_encoded_val(&a.to_vec());
    }
}


#[cfg(test)]
mod tests {
    use super::super::{
        DecodeError,
        decode_ssz_list_element,
    };

    #[test]
    fn test_ssz_decode_u16() {
        let ssz = vec![0, 0, 0, 1, 0];
        let result: u16 = decode_ssz_list_element(&ssz, 0).unwrap();
        assert_eq!(result, 0);

        let ssz = vec![0, 0, 0, 1, 16];
        let result: u16 = decode_ssz_list_element(&ssz, 0).unwrap();
        assert_eq!(result, 16);

        let ssz = vec![0, 0, 0, 2, 1, 0];
        let result: u16 = decode_ssz_list_element(&ssz, 0).unwrap();
        assert_eq!(result, 256);

        let ssz = vec![0, 0, 0, 2, 255, 255];
        let result: u16 = decode_ssz_list_element(&ssz, 0).unwrap();
        assert_eq!(result, 65535);

        let ssz = vec![0, 0, 0, 3, 0, 0, 1];
        let result: Result<u16, DecodeError> =
            decode_ssz_list_element(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooLong));
    }

    #[test]
    fn test_ssz_decode_u32() {
        let ssz = vec![0, 0, 0, 1, 0];
        let result: u32 = decode_ssz_list_element(&ssz, 0).unwrap();
        assert_eq!(result, 0);

        let ssz = vec![0, 0, 0, 4, 255, 255, 255, 255];
        let result: u32 = decode_ssz_list_element(&ssz, 0).unwrap();
        assert_eq!(result, 4294967295);

        let ssz = vec![0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let result: Result<u32, DecodeError> =
            decode_ssz_list_element(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooLong));
    }

    #[test]
    fn test_ssz_decode_u64() {
        let ssz = vec![0, 0, 0, 1, 0];
        let result: u64 = decode_ssz_list_element(&ssz, 0).unwrap();
        assert_eq!(result, 0);

        let ssz = vec![0, 0, 0, 8, 255, 255, 255, 255, 255, 255, 255, 255];
        let result: u64 = decode_ssz_list_element(&ssz, 0).unwrap();
        assert_eq!(result, 18446744073709551615);

        let ssz = vec![0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let result: Result<u64, DecodeError> =
            decode_ssz_list_element(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooLong));
    }

    #[test]
    fn test_ssz_decode_usize() {
        let ssz = vec![0, 0, 0, 1, 0];
        let result: usize = decode_ssz_list_element(&ssz, 0).unwrap();
        assert_eq!(result, 0);

        let ssz = vec![0, 0, 0, 8, 255, 255, 255, 255, 255, 255, 255, 255];
        let result: usize = decode_ssz_list_element(&ssz, 0).unwrap();
        assert_eq!(result, 18446744073709551615);

        let ssz = vec![0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let result: Result<usize, DecodeError> =
            decode_ssz_list_element(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooLong));
    }
}
