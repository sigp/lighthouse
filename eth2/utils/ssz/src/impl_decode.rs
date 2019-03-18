use super::decode::decode_ssz_list;
use super::ethereum_types::{Address, H256};
use super::{Decodable, DecodeError};

macro_rules! impl_decodable_for_uint {
    ($type: ident, $bit_size: expr) => {
        impl Decodable for $type {
            fn ssz_decode(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
                assert!((0 < $bit_size) & ($bit_size <= 64) & ($bit_size % 8 == 0));
                let max_bytes = $bit_size / 8;
                if bytes.len() >= (index + max_bytes) {
                    let end_bytes = index + max_bytes;
                    let mut result: $type = 0;
                    for (i, byte) in bytes.iter().enumerate().take(end_bytes).skip(index) {
                        let offset = (i - index) * 8;
                        result |= ($type::from(*byte)) << offset;
                    }
                    Ok((result, end_bytes))
                } else {
                    Err(DecodeError::TooShort)
                }
            }
        }
    };
}

impl_decodable_for_uint!(u16, 16);
impl_decodable_for_uint!(u32, 32);
impl_decodable_for_uint!(u64, 64);
impl_decodable_for_uint!(usize, 64);

impl Decodable for u8 {
    fn ssz_decode(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
        if index >= bytes.len() {
            Err(DecodeError::TooShort)
        } else {
            Ok((bytes[index], index + 1))
        }
    }
}

impl Decodable for bool {
    fn ssz_decode(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
        if index >= bytes.len() {
            Err(DecodeError::TooShort)
        } else {
            let result = match bytes[index] {
                0b0000_0000 => false,
                0b0000_0001 => true,
                _ => return Err(DecodeError::Invalid),
            };
            Ok((result, index + 1))
        }
    }
}

impl Decodable for H256 {
    fn ssz_decode(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
        if bytes.len() < 32 || bytes.len() - 32 < index {
            Err(DecodeError::TooShort)
        } else {
            Ok((H256::from_slice(&bytes[index..(index + 32)]), index + 32))
        }
    }
}

impl Decodable for Address {
    fn ssz_decode(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
        if bytes.len() < 20 || bytes.len() - 20 < index {
            Err(DecodeError::TooShort)
        } else {
            Ok((Address::from_slice(&bytes[index..(index + 20)]), index + 20))
        }
    }
}

impl<T> Decodable for Vec<T>
where
    T: Decodable,
{
    fn ssz_decode(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
        decode_ssz_list(bytes, index)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{decode, DecodeError};
    use super::*;

    #[test]
    fn test_ssz_decode_h256() {
        /*
         * Input is exact length
         */
        let input = vec![42_u8; 32];
        let (decoded, i) = H256::ssz_decode(&input, 0).unwrap();
        assert_eq!(decoded.as_bytes(), &input[..]);
        assert_eq!(i, 32);

        /*
         * Input is too long
         */
        let mut input = vec![42_u8; 32];
        input.push(12);
        let (decoded, i) = H256::ssz_decode(&input, 0).unwrap();
        assert_eq!(decoded.as_bytes(), &input[0..32]);
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

        let (result, index): (u16, usize) = <_>::ssz_decode(&ssz, 0).unwrap();
        assert_eq!(result, 0);
        assert_eq!(index, 2);

        let ssz = vec![16, 0];
        let (result, index): (u16, usize) = <_>::ssz_decode(&ssz, 0).unwrap();
        assert_eq!(result, 16);
        assert_eq!(index, 2);

        let ssz = vec![0, 1];
        let (result, index): (u16, usize) = <_>::ssz_decode(&ssz, 0).unwrap();
        assert_eq!(result, 256);
        assert_eq!(index, 2);

        let ssz = vec![255, 255];
        let (result, index): (u16, usize) = <_>::ssz_decode(&ssz, 0).unwrap();
        assert_eq!(index, 2);
        assert_eq!(result, 65535);

        let ssz = vec![1];
        let result: Result<(u16, usize), DecodeError> = <_>::ssz_decode(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn test_ssz_decode_u32() {
        let ssz = vec![0, 0, 0, 0];
        let (result, index): (u32, usize) = <_>::ssz_decode(&ssz, 0).unwrap();
        assert_eq!(result, 0);
        assert_eq!(index, 4);

        let ssz = vec![0, 1, 0, 0];
        let (result, index): (u32, usize) = <_>::ssz_decode(&ssz, 0).unwrap();
        assert_eq!(index, 4);
        assert_eq!(result, 256);

        let ssz = vec![255, 255, 255, 0, 1, 0, 0];
        let (result, index): (u32, usize) = <_>::ssz_decode(&ssz, 3).unwrap();
        assert_eq!(index, 7);
        assert_eq!(result, 256);

        let ssz = vec![0, 1, 200, 0];
        let (result, index): (u32, usize) = <_>::ssz_decode(&ssz, 0).unwrap();
        assert_eq!(index, 4);
        assert_eq!(result, 13107456);

        let ssz = vec![255, 255, 255, 255];
        let (result, index): (u32, usize) = <_>::ssz_decode(&ssz, 0).unwrap();
        assert_eq!(index, 4);
        assert_eq!(result, 4294967295);

        let ssz = vec![1, 0, 0];
        let result: Result<(u32, usize), DecodeError> = <_>::ssz_decode(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn test_ssz_decode_u64() {
        let ssz = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let (result, index): (u64, usize) = <_>::ssz_decode(&ssz, 0).unwrap();
        assert_eq!(index, 8);
        assert_eq!(result, 0);

        let ssz = vec![255, 255, 255, 255, 255, 255, 255, 255];
        let (result, index): (u64, usize) = <_>::ssz_decode(&ssz, 0).unwrap();
        assert_eq!(index, 8);
        assert_eq!(result, 18446744073709551615);

        let ssz = vec![0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 255];
        let (result, index): (u64, usize) = <_>::ssz_decode(&ssz, 3).unwrap();
        assert_eq!(index, 11);
        assert_eq!(result, 18374686479671623680);

        let ssz = vec![0, 0, 0, 0, 0, 0, 0];
        let result: Result<(u64, usize), DecodeError> = <_>::ssz_decode(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn test_ssz_decode_usize() {
        let ssz = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let (result, index): (usize, usize) = <_>::ssz_decode(&ssz, 0).unwrap();
        assert_eq!(index, 8);
        assert_eq!(result, 0);

        let ssz = vec![0, 0, 8, 255, 255, 255, 255, 255, 255, 255, 255];
        let (result, index): (usize, usize) = <_>::ssz_decode(&ssz, 3).unwrap();
        assert_eq!(index, 11);
        assert_eq!(result, 18446744073709551615);

        let ssz = vec![255, 255, 255, 255, 255, 255, 255, 255, 255];
        let (result, index): (usize, usize) = <_>::ssz_decode(&ssz, 0).unwrap();
        assert_eq!(index, 8);
        assert_eq!(result, 18446744073709551615);

        let ssz = vec![0, 0, 0, 0, 0, 0, 1];
        let result: Result<(usize, usize), DecodeError> = <_>::ssz_decode(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn test_decode_ssz_bounds() {
        let err: Result<(u16, usize), DecodeError> = <_>::ssz_decode(&vec![1], 2);
        assert_eq!(err, Err(DecodeError::TooShort));

        let err: Result<(u16, usize), DecodeError> = <_>::ssz_decode(&vec![0, 0, 0, 0], 3);
        assert_eq!(err, Err(DecodeError::TooShort));

        let result: u16 = <_>::ssz_decode(&vec![0, 0, 0, 1, 0], 3).unwrap().0;
        assert_eq!(result, 1);
    }

    #[test]
    fn test_decode_ssz_bool() {
        let ssz = vec![0b0000_0000, 0b0000_0001];
        let (result, index): (bool, usize) = <_>::ssz_decode(&ssz, 0).unwrap();
        assert_eq!(index, 1);
        assert_eq!(result, false);

        let (result, index): (bool, usize) = <_>::ssz_decode(&ssz, 1).unwrap();
        assert_eq!(index, 2);
        assert_eq!(result, true);

        let ssz = vec![0b0100_0000];
        let result: Result<(bool, usize), DecodeError> = <_>::ssz_decode(&ssz, 0);
        assert_eq!(result, Err(DecodeError::Invalid));

        let ssz = vec![];
        let result: Result<(bool, usize), DecodeError> = <_>::ssz_decode(&ssz, 0);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    #[should_panic]
    fn test_decode_ssz_list_underflow() {
        // SSZ encoded (u16::[1, 1, 1], u16::2)
        let mut encoded = vec![6, 0, 0, 0, 1, 0, 1, 0, 1, 0, 2, 0];
        let (decoded_array, i): (Vec<u16>, usize) = <_>::ssz_decode(&encoded, 0).unwrap();
        let (decoded_u16, i): (u16, usize) = <_>::ssz_decode(&encoded, i).unwrap();
        assert_eq!(decoded_array, vec![1, 1, 1]);
        assert_eq!(decoded_u16, 2);
        assert_eq!(i, 12);

        // Underflow
        encoded[0] = 4; // change length to 4 from 6
        let (decoded_array, i): (Vec<u16>, usize) = <_>::ssz_decode(&encoded, 0).unwrap();
        let (decoded_u16, _): (u16, usize) = <_>::ssz_decode(&encoded, i).unwrap();
        assert_eq!(decoded_array, vec![1, 1]);
        assert_eq!(decoded_u16, 2);
    }

    #[test]
    fn test_decode_too_long() {
        let encoded = vec![6, 0, 0, 0, 1, 0, 1, 0, 1, 0, 2];
        let decoded_array: Result<Vec<u16>, DecodeError> = decode(&encoded);
        assert_eq!(decoded_array, Err(DecodeError::TooLong));
    }
}
