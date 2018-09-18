use super::{
    DecodeError,
    Decodable,
};
macro_rules! impl_decodable_for_uint {
    ($type: ident, $bit_size: expr) => {
        impl Decodable for $type {
            fn ssz_decode(bytes: &[u8], index: usize)
                -> Result<Self, DecodeError>
            {
                assert!((0 < $bit_size) &
                        ($bit_size <= 64) &
                        ($bit_size % 8 == 0));
                let max_bytes = $bit_size / 8;
                if bytes.len() >= (index + max_bytes) {
                    let end_bytes = index + max_bytes;
                    let mut result: $type = 0;
                    for i in index..end_bytes {
                        let offset = ((index + max_bytes) - i - 1) * 8;
                        result = ((bytes[i] as $type) << offset) | result;
                    };
                    Ok(result)
                } else {
                    Err(DecodeError::TooShort)
                }
            }
        }
    }
}

impl_decodable_for_uint!(u16, 16);
impl_decodable_for_uint!(u32, 32);
impl_decodable_for_uint!(u64, 64);
impl_decodable_for_uint!(usize, 64);


#[cfg(test)]
mod tests {
    use super::super::{
        DecodeError,
        decode_ssz,
    };

    #[test]
    fn test_ssz_decode_u16() {
        let ssz = vec![0, 0];
        let result: u16 = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 0);

        let ssz = vec![0, 16];
        let result: u16 = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 16);

        let ssz = vec![1, 0];
        let result: u16 = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 256);

        let ssz = vec![255, 255];
        let result: u16 = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 65535);

        let ssz = vec![1];
        let result: Result<u16, DecodeError> =
            decode_ssz(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn test_ssz_decode_u32() {
        let ssz = vec![0, 0, 0, 0];
        let result: u32 = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 0);

        let ssz = vec![0, 0, 1, 0];
        let result: u32 = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 256);

        let ssz = vec![255, 255, 255, 0, 0, 1, 0];
        let result: u32 = decode_ssz(&ssz, 3).unwrap();
        assert_eq!(result, 256);

        let ssz = vec![0,200, 1, 0];
        let result: u32 = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 13107456);

        let ssz = vec![255, 255, 255, 255];
        let result: u32 = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 4294967295);

        let ssz = vec![0, 0, 1];
        let result: Result<u32, DecodeError> =
            decode_ssz(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn test_ssz_decode_u64() {
        let ssz = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let result: u64 = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 0);

        let ssz = vec![255, 255, 255, 255, 255, 255, 255, 255];
        let result: u64 = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 18446744073709551615);

        let ssz = vec![255, 255, 255, 0, 0, 0, 0, 0, 0, 0];
        let result: u64 = decode_ssz(&ssz, 2).unwrap();
        assert_eq!(result, 18374686479671623680);

        let ssz = vec![0,0,0,0,0,0,0];
        let result: Result<u64, DecodeError> =
            decode_ssz(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn test_ssz_decode_usize() {
        let ssz = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let result: usize = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 0);

        let ssz = vec![0, 0, 8, 255, 255, 255, 255, 255, 255, 255, 255];
        let result: usize = decode_ssz(&ssz, 3).unwrap();
        assert_eq!(result, 18446744073709551615);

        let ssz = vec![255, 255, 255, 255, 255, 255, 255, 255];
        let result: usize = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 18446744073709551615);

        let ssz = vec![0, 0, 0, 0, 0, 0, 1];
        let result: Result<usize, DecodeError> =
            decode_ssz(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn test_decode_ssz_bounds() {
        let err: Result<u16, DecodeError> = decode_ssz(
            &vec![1],
            2
        );
        assert_eq!(err, Err(DecodeError::OutOfBounds));

        let err: Result<u16, DecodeError> = decode_ssz(
            &vec![0, 0, 0, 0],
            3
        );
        assert_eq!(err, Err(DecodeError::TooShort));

        let result: u16 = decode_ssz(
            &vec![0,0,0,0,1],
            3
        ).unwrap();
        assert_eq!(result, 1);
    }
}
