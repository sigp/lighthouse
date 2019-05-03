use super::*;

macro_rules! impl_decodable_for_uint {
    ($type: ident, $bit_size: expr) => {
        impl Decodable for $type {
            fn is_ssz_fixed_len() -> bool {
                true
            }

            fn ssz_fixed_len() -> usize {
                $bit_size / 8
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
                let len = bytes.len();
                let expected = <Self as Decodable>::ssz_fixed_len();

                if len != expected {
                    Err(DecodeError::InvalidByteLength { len, expected })
                } else {
                    let mut array: [u8; $bit_size / 8] = std::default::Default::default();
                    array.clone_from_slice(bytes);

                    Ok(Self::from_le_bytes(array))
                }
            }
        }
    };
}

impl_decodable_for_uint!(u16, 16);
impl_decodable_for_uint!(u32, 32);
impl_decodable_for_uint!(u64, 64);
impl_decodable_for_uint!(usize, 64);

impl<T: Decodable> Decodable for Vec<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() == 0 {
            Ok(vec![])
        } else if T::is_ssz_fixed_len() {
            bytes
                .chunks(T::ssz_fixed_len())
                .map(|chunk| T::from_ssz_bytes(chunk))
                .collect()
        } else {
            let mut next_variable_byte = read_offset(bytes)?;

            // The value of the first offset must not point back into the same bytes that defined
            // it.
            if next_variable_byte < BYTES_PER_LENGTH_OFFSET {
                return Err(DecodeError::OutOfBoundsByte {
                    i: next_variable_byte,
                });
            }

            let num_items = next_variable_byte / BYTES_PER_LENGTH_OFFSET;

            // The fixed-length section must be a clean multiple of `BYTES_PER_LENGTH_OFFSET`.
            if next_variable_byte != num_items * BYTES_PER_LENGTH_OFFSET {
                return Err(DecodeError::InvalidByteLength {
                    len: next_variable_byte,
                    expected: num_items * BYTES_PER_LENGTH_OFFSET,
                });
            }

            let mut values = Vec::with_capacity(num_items);
            for i in 1..=num_items {
                let slice_option = if i == num_items {
                    bytes.get(next_variable_byte..)
                } else {
                    let offset = read_offset(&bytes[(i * BYTES_PER_LENGTH_OFFSET)..])?;

                    let start = next_variable_byte;
                    next_variable_byte = offset;

                    // Note: the condition where `start > next_variable_byte` returns `None` which
                    // raises an error later in the program.
                    bytes.get(start..next_variable_byte)
                };

                let slice = slice_option.ok_or_else(|| DecodeError::OutOfBoundsByte {
                    i: next_variable_byte,
                })?;

                values.push(T::from_ssz_bytes(slice)?);
            }

            Ok(values)
        }
    }
}

/// Reads a `BYTES_PER_LENGTH_OFFSET`-byte length from `bytes`, where `bytes.len() >=
/// BYTES_PER_LENGTH_OFFSET`.
fn read_offset(bytes: &[u8]) -> Result<usize, DecodeError> {
    decode_offset(bytes.get(0..BYTES_PER_LENGTH_OFFSET).ok_or_else(|| {
        DecodeError::InvalidLengthPrefix {
            len: bytes.len(),
            expected: BYTES_PER_LENGTH_OFFSET,
        }
    })?)
}

/// Decode bytes as a little-endian usize, returning an `Err` if `bytes.len() !=
/// BYTES_PER_LENGTH_OFFSET`.
pub fn decode_offset(bytes: &[u8]) -> Result<usize, DecodeError> {
    let len = bytes.len();
    let expected = BYTES_PER_LENGTH_OFFSET;

    if len != expected {
        Err(DecodeError::InvalidLengthPrefix { len, expected })
    } else {
        let mut array: [u8; BYTES_PER_LENGTH_OFFSET] = std::default::Default::default();
        array.clone_from_slice(bytes);

        Ok(u32::from_le_bytes(array) as usize)
    }
}

/*
use super::decode::decode_ssz_list;
use super::ethereum_types::{Address, H256};
use super::{Decodable, DecodeError};

macro_rules! impl_decodable_for_uint {
    ($type: ident, $bit_size: expr) => {
        impl Decodable for $type {
            fn from_ssz_bytes(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
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

macro_rules! impl_decodable_for_u8_array {
    ($len: expr) => {
        impl Decodable for [u8; $len] {
            fn from_ssz_bytes(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
                if index + $len > bytes.len() {
                    Err(DecodeError::TooShort)
                } else {
                    let mut array: [u8; $len] = [0; $len];
                    array.copy_from_slice(&bytes[index..index + $len]);

                    Ok((array, index + $len))
                }
            }
        }
    };
}

impl_decodable_for_uint!(u16, 16);
impl_decodable_for_uint!(u32, 32);
impl_decodable_for_uint!(u64, 64);
impl_decodable_for_uint!(usize, 64);

impl_decodable_for_u8_array!(4);

impl Decodable for u8 {
    fn from_ssz_bytes(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
        if index >= bytes.len() {
            Err(DecodeError::TooShort)
        } else {
            Ok((bytes[index], index + 1))
        }
    }
}

impl Decodable for bool {
    fn from_ssz_bytes(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
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
    fn from_ssz_bytes(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
        if bytes.len() < 32 || bytes.len() - 32 < index {
            Err(DecodeError::TooShort)
        } else {
            Ok((H256::from_slice(&bytes[index..(index + 32)]), index + 32))
        }
    }
}

impl Decodable for Address {
    fn from_ssz_bytes(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
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
    fn from_ssz_bytes(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
        decode_ssz_list(bytes, index)
    }
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    /*
    #[test]
    fn from_ssz_bytes_h256() {
        /*
         * Input is exact length
         */
        let input = vec![42_u8; 32];
        let (decoded, i) = H256::from_ssz_bytes(&input).unwrap();
        assert_eq!(decoded.as_bytes(), &input[..]);
        assert_eq!(i, 32);

        /*
         * Input is too long
         */
        let mut input = vec![42_u8; 32];
        input.push(12);
        let (decoded, i) = H256::from_ssz_bytes(&input, 0).unwrap();
        assert_eq!(decoded.as_bytes(), &input[0..32]);
        assert_eq!(i, 32);

        /*
         * Input is too short
         */
        let input = vec![42_u8; 31];
        let res = H256::from_ssz_bytes(&input, 0);
        assert_eq!(res, Err(DecodeError::TooShort));
    }
    */

    #[test]
    fn first_length_points_backwards() {
        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[0, 0, 0, 0]),
            Err(DecodeError::OutOfBoundsByte { i: 0 })
        );

        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[1, 0, 0, 0]),
            Err(DecodeError::OutOfBoundsByte { i: 1 })
        );

        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[2, 0, 0, 0]),
            Err(DecodeError::OutOfBoundsByte { i: 2 })
        );

        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[3, 0, 0, 0]),
            Err(DecodeError::OutOfBoundsByte { i: 3 })
        );
    }

    #[test]
    fn lengths_are_decreasing() {
        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[12, 0, 0, 0, 14, 0, 0, 0, 12, 0, 0, 0, 1, 0, 1, 0]),
            Err(DecodeError::OutOfBoundsByte { i: 12 })
        );
    }

    #[test]
    fn awkward_fixed_lenth_portion() {
        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[10, 0, 0, 0, 10, 0, 0, 0, 0, 0]),
            Err(DecodeError::InvalidByteLength {
                len: 10,
                expected: 8
            })
        );
    }

    #[test]
    fn length_out_of_bounds() {
        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[5, 0, 0, 0]),
            Err(DecodeError::InvalidByteLength {
                len: 5,
                expected: 4
            })
        );
        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[8, 0, 0, 0, 9, 0, 0, 0]),
            Err(DecodeError::OutOfBoundsByte { i: 9 })
        );
    }

    #[test]
    fn vec_of_vec_of_u16() {
        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[4, 0, 0, 0]),
            Ok(vec![vec![]])
        );

        /*
        assert_eq!(
            <Vec<u16>>::from_ssz_bytes(&[0, 0, 1, 0, 2, 0, 3, 0]),
            Ok(vec![0, 1, 2, 3])
        );
        assert_eq!(<u16>::from_ssz_bytes(&[16, 0]), Ok(16));
        assert_eq!(<u16>::from_ssz_bytes(&[0, 1]), Ok(256));
        assert_eq!(<u16>::from_ssz_bytes(&[255, 255]), Ok(65535));

        assert_eq!(
            <u16>::from_ssz_bytes(&[255]),
            Err(DecodeError::InvalidByteLength {
                len: 1,
                expected: 2
            })
        );

        assert_eq!(
            <u16>::from_ssz_bytes(&[]),
            Err(DecodeError::InvalidByteLength {
                len: 0,
                expected: 2
            })
        );

        assert_eq!(
            <u16>::from_ssz_bytes(&[0, 1, 2]),
            Err(DecodeError::InvalidByteLength {
                len: 3,
                expected: 2
            })
        );
        */
    }

    #[test]
    fn vec_of_u16() {
        assert_eq!(<Vec<u16>>::from_ssz_bytes(&[0, 0, 0, 0]), Ok(vec![0, 0]));
        assert_eq!(
            <Vec<u16>>::from_ssz_bytes(&[0, 0, 1, 0, 2, 0, 3, 0]),
            Ok(vec![0, 1, 2, 3])
        );
        assert_eq!(<u16>::from_ssz_bytes(&[16, 0]), Ok(16));
        assert_eq!(<u16>::from_ssz_bytes(&[0, 1]), Ok(256));
        assert_eq!(<u16>::from_ssz_bytes(&[255, 255]), Ok(65535));

        assert_eq!(
            <u16>::from_ssz_bytes(&[255]),
            Err(DecodeError::InvalidByteLength {
                len: 1,
                expected: 2
            })
        );

        assert_eq!(
            <u16>::from_ssz_bytes(&[]),
            Err(DecodeError::InvalidByteLength {
                len: 0,
                expected: 2
            })
        );

        assert_eq!(
            <u16>::from_ssz_bytes(&[0, 1, 2]),
            Err(DecodeError::InvalidByteLength {
                len: 3,
                expected: 2
            })
        );
    }

    #[test]
    fn u16() {
        assert_eq!(<u16>::from_ssz_bytes(&[0, 0]), Ok(0));
        assert_eq!(<u16>::from_ssz_bytes(&[16, 0]), Ok(16));
        assert_eq!(<u16>::from_ssz_bytes(&[0, 1]), Ok(256));
        assert_eq!(<u16>::from_ssz_bytes(&[255, 255]), Ok(65535));

        assert_eq!(
            <u16>::from_ssz_bytes(&[255]),
            Err(DecodeError::InvalidByteLength {
                len: 1,
                expected: 2
            })
        );

        assert_eq!(
            <u16>::from_ssz_bytes(&[]),
            Err(DecodeError::InvalidByteLength {
                len: 0,
                expected: 2
            })
        );

        assert_eq!(
            <u16>::from_ssz_bytes(&[0, 1, 2]),
            Err(DecodeError::InvalidByteLength {
                len: 3,
                expected: 2
            })
        );
    }

    /*
    #[test]
    fn from_ssz_bytes_u32() {
        let ssz = vec![0, 0, 0, 0];
        let (result, index): (u32, usize) = <_>::from_ssz_bytes(&ssz).unwrap();
        assert_eq!(result, 0);
        assert_eq!(index, 4);

        let ssz = vec![0, 1, 0, 0];
        let (result, index): (u32, usize) = <_>::from_ssz_bytes(&ssz).unwrap();
        assert_eq!(index, 4);
        assert_eq!(result, 256);

        let ssz = vec![255, 255, 255, 0, 1, 0, 0];
        let (result, index): (u32, usize) = <_>::from_ssz_bytes(&ssz, 3).unwrap();
        assert_eq!(index, 7);
        assert_eq!(result, 256);

        let ssz = vec![0, 1, 200, 0];
        let (result, index): (u32, usize) = <_>::from_ssz_bytes(&ssz).unwrap();
        assert_eq!(index, 4);
        assert_eq!(result, 13107456);

        let ssz = vec![255, 255, 255, 255];
        let (result, index): (u32, usize) = <_>::from_ssz_bytes(&ssz).unwrap();
        assert_eq!(index, 4);
        assert_eq!(result, 4294967295);

        let ssz = vec![1, 0, 0];
        let result: Result<(u32, usize), DecodeError> = <_>::from_ssz_bytes(&ssz);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn from_ssz_bytes_u64() {
        let ssz = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let (result, index): (u64, usize) = <_>::from_ssz_bytes(&ssz).unwrap();
        assert_eq!(index, 8);
        assert_eq!(result, 0);

        let ssz = vec![255, 255, 255, 255, 255, 255, 255, 255];
        let (result, index): (u64, usize) = <_>::from_ssz_bytes(&ssz).unwrap();
        assert_eq!(index, 8);
        assert_eq!(result, 18446744073709551615);

        let ssz = vec![0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 255];
        let (result, index): (u64, usize) = <_>::from_ssz_bytes(&ssz, 3).unwrap();
        assert_eq!(index, 11);
        assert_eq!(result, 18374686479671623680);

        let ssz = vec![0, 0, 0, 0, 0, 0, 0];
        let result: Result<(u64, usize), DecodeError> = <_>::from_ssz_bytes(&ssz);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn from_ssz_bytes_usize() {
        let ssz = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let (result, index): (usize, usize) = <_>::from_ssz_bytes(&ssz).unwrap();
        assert_eq!(index, 8);
        assert_eq!(result, 0);

        let ssz = vec![0, 0, 8, 255, 255, 255, 255, 255, 255, 255, 255];
        let (result, index): (usize, usize) = <_>::from_ssz_bytes(&ssz, 3).unwrap();
        assert_eq!(index, 11);
        assert_eq!(result, 18446744073709551615);

        let ssz = vec![255, 255, 255, 255, 255, 255, 255, 255, 255];
        let (result, index): (usize, usize) = <_>::from_ssz_bytes(&ssz).unwrap();
        assert_eq!(index, 8);
        assert_eq!(result, 18446744073709551615);

        let ssz = vec![0, 0, 0, 0, 0, 0, 1];
        let result: Result<(usize, usize), DecodeError> = <_>::from_ssz_bytes(&ssz);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    fn decode_ssz_bounds() {
        let err: Result<(u16, usize), DecodeError> = <_>::from_ssz_bytes(&vec![1], 2);
        assert_eq!(err, Err(DecodeError::TooShort));

        let err: Result<(u16, usize), DecodeError> = <_>::from_ssz_bytes(&vec![0, 0, 0, 0], 3);
        assert_eq!(err, Err(DecodeError::TooShort));

        let result: u16 = <_>::from_ssz_bytes(&vec![0, 0, 0, 1, 0], 3).unwrap().0;
        assert_eq!(result, 1);
    }

    #[test]
    fn decode_ssz_bool() {
        let ssz = vec![0b0000_0000, 0b0000_0001];
        let (result, index): (bool, usize) = <_>::from_ssz_bytes(&ssz).unwrap();
        assert_eq!(index, 1);
        assert_eq!(result, false);

        let (result, index): (bool, usize) = <_>::from_ssz_bytes(&ssz, 1).unwrap();
        assert_eq!(index, 2);
        assert_eq!(result, true);

        let ssz = vec![0b0100_0000];
        let result: Result<(bool, usize), DecodeError> = <_>::from_ssz_bytes(&ssz);
        assert_eq!(result, Err(DecodeError::Invalid));

        let ssz = vec![];
        let result: Result<(bool, usize), DecodeError> = <_>::from_ssz_bytes(&ssz);
        assert_eq!(result, Err(DecodeError::TooShort));
    }

    #[test]
    #[should_panic]
    fn decode_ssz_list_underflow() {
        // SSZ encoded (u16::[1, 1, 1], u16::2)
        let mut encoded = vec![6, 0, 0, 0, 1, 0, 1, 0, 1, 0, 2, 0];
        let (decoded_array, i): (Vec<u16>, usize) = <_>::from_ssz_bytes(&encoded, 0).unwrap();
        let (decoded_u16, i): (u16, usize) = <_>::from_ssz_bytes(&encoded, i).unwrap();
        assert_eq!(decoded_array, vec![1, 1, 1]);
        assert_eq!(decoded_u16, 2);
        assert_eq!(i, 12);

        // Underflow
        encoded[0] = 4; // change length to 4 from 6
        let (decoded_array, i): (Vec<u16>, usize) = <_>::from_ssz_bytes(&encoded, 0).unwrap();
        let (decoded_u16, _): (u16, usize) = <_>::from_ssz_bytes(&encoded, i).unwrap();
        assert_eq!(decoded_array, vec![1, 1]);
        assert_eq!(decoded_u16, 2);
    }

    #[test]
    fn decode_too_long() {
        let encoded = vec![6, 0, 0, 0, 1, 0, 1, 0, 1, 0, 2];
        let decoded_array: Result<Vec<u16>, DecodeError> = decode(&encoded);
        assert_eq!(decoded_array, Err(DecodeError::TooLong));
    }

    #[test]
    fn decode_u8_array() {
        let ssz = vec![0, 1, 2, 3];
        let result: [u8; 4] = decode(&ssz).unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result, [0, 1, 2, 3]);
    }
    */
}
