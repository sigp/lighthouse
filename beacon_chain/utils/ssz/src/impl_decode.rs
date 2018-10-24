use super::ethereum_types::H256;
use super::decode::decode_ssz_list;
use super::{
    DecodeError,
    Decodable,
};


macro_rules! impl_decodable_for_uint {
    ($type: ident, $bit_size: expr) => {
        impl Decodable for $type {
            fn ssz_decode(bytes: &[u8], index: usize)
                -> Result<(Self, usize), DecodeError>
            {
                assert!((0 < $bit_size) &
                        ($bit_size <= 64) &
                        ($bit_size % 8 == 0));
                let max_bytes = $bit_size / 8;
                if bytes.len() >= (index + max_bytes) {
                    let end_bytes = index + max_bytes;
                    let mut result: $type = 0;
                    for (i, byte) in bytes.iter().enumerate().take(end_bytes).skip(index) {
                        let offset = (end_bytes - i - 1) * 8;
                        result |= ($type::from(*byte)) << offset;
                    }
                    Ok((result, end_bytes))
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

impl Decodable for u8 {
    fn ssz_decode(bytes: &[u8], index: usize)
        -> Result<(Self, usize), DecodeError>
    {
        if index >= bytes.len() {
            Err(DecodeError::TooShort)
        } else {
            Ok((bytes[index], index + 1))
        }
    }
}

impl Decodable for H256 {
    fn ssz_decode(bytes: &[u8], index: usize)
        -> Result<(Self, usize), DecodeError>
    {
        if bytes.len() < 32 || bytes.len() - 32 < index {
            Err(DecodeError::TooShort)
        }
        else {
            Ok((H256::from(&bytes[index..(index + 32)]), index + 32))
        }
    }
}

impl<T> Decodable for Vec<T>
    where T: Decodable
{
    fn ssz_decode(bytes: &[u8], index: usize)
        -> Result<(Self, usize), DecodeError>
    {
        decode_ssz_list(bytes, index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{
        DecodeError,
        decode_ssz,
    };

    #[test]
    fn test_ssz_decode_h256() {
        /*
         * Input is exact length
         */
        let input = vec![42_u8; 32];
        let (decoded, i) = H256::ssz_decode(&input, 0).unwrap();
        assert_eq!(decoded.to_vec(), input);
        assert_eq!(i, 32);

        /*
         * Input is too long
         */
        let mut input = vec![42_u8; 32];
        input.push(12);
        let (decoded, i) = H256::ssz_decode(&input, 0).unwrap();
        assert_eq!(decoded.to_vec()[..], input[0..32]);
        assert_eq!(i, 32);

        /*
         * Input is too short
         */
        let input = vec![42_u8; 31];
        let res = H256::ssz_decode(&input, 0);
        assert_eq!(res, Err(DecodeError::TooShort));
    }

    #[test]
    fn test_ssz_decode_u16() {
        let ssz = vec![0, 0];

        let (result, index): (u16, usize) = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 0);
        assert_eq!(index, 2);

        let ssz = vec![0, 16];
        let (result, index): (u16, usize) = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 16);
        assert_eq!(index, 2);

        let ssz = vec![1, 0];
        let (result, index): (u16, usize) = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 256);
        assert_eq!(index, 2);

        let ssz = vec![255, 255];
        let (result, index): (u16, usize) = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(index, 2);
        assert_eq!(result, 65535);

        let ssz = vec![1];
        let result: Result<(u16, usize), DecodeError> =
            decode_ssz(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn test_ssz_decode_u32() {
        let ssz = vec![0, 0, 0, 0];
        let (result, index): (u32, usize) = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(result, 0);
        assert_eq!(index, 4);

        let ssz = vec![0, 0, 1, 0];
        let (result, index): (u32, usize) = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(index, 4);
        assert_eq!(result, 256);

        let ssz = vec![255, 255, 255, 0, 0, 1, 0];
        let (result, index): (u32, usize) = decode_ssz(&ssz, 3).unwrap();
        assert_eq!(index, 7);
        assert_eq!(result, 256);

        let ssz = vec![0,200, 1, 0];
        let (result, index): (u32, usize) = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(index, 4);
        assert_eq!(result, 13107456);

        let ssz = vec![255, 255, 255, 255];
        let (result, index): (u32, usize) = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(index, 4);
        assert_eq!(result, 4294967295);

        let ssz = vec![0, 0, 1];
        let result: Result<(u32, usize), DecodeError> =
            decode_ssz(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn test_ssz_decode_u64() {
        let ssz = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let (result, index): (u64, usize) = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(index, 8);
        assert_eq!(result, 0);

        let ssz = vec![255, 255, 255, 255, 255, 255, 255, 255];
        let (result, index): (u64, usize) = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(index, 8);
        assert_eq!(result, 18446744073709551615);

        let ssz = vec![0, 0, 8, 255, 0, 0, 0, 0, 0, 0, 0];
        let (result, index): (u64, usize) = decode_ssz(&ssz, 3).unwrap();
        assert_eq!(index, 11);
        assert_eq!(result, 18374686479671623680);

        let ssz = vec![0,0,0,0,0,0,0];
        let result: Result<(u64, usize), DecodeError> =
            decode_ssz(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn test_ssz_decode_usize() {
        let ssz = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let (result, index): (usize, usize) = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(index, 8);
        assert_eq!(result, 0);

        let ssz = vec![0, 0, 8, 255, 255, 255, 255, 255, 255, 255, 255];
        let (result, index): (usize, usize) = decode_ssz(&ssz, 3).unwrap();
        assert_eq!(index, 11);
        assert_eq!(result, 18446744073709551615);

        let ssz = vec![255, 255, 255, 255, 255, 255, 255, 255, 255];
        let (result, index): (usize, usize) = decode_ssz(&ssz, 0).unwrap();
        assert_eq!(index, 8);
        assert_eq!(result, 18446744073709551615);

        let ssz = vec![0, 0, 0, 0, 0, 0, 1];
        let result: Result<(usize, usize), DecodeError> =
            decode_ssz(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn test_decode_ssz_bounds() {
        let err: Result<(u16, usize), DecodeError> = decode_ssz(
            &vec![1],
            2
        );
        assert_eq!(err, Err(DecodeError::TooShort));

        let err: Result<(u16,usize), DecodeError> = decode_ssz(
            &vec![0, 0, 0, 0],
            3
        );
        assert_eq!(err, Err(DecodeError::TooShort));

        let result: u16 = decode_ssz(
            &vec![0,0,0,0,1],
            3
        ).unwrap().0;
        assert_eq!(result, 1);
    }
}
