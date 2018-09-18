use super::{
    LENGTH_BYTES,
};

#[derive(Debug, PartialEq)]
pub enum DecodeError {
    OutOfBounds,
    TooShort,
    TooLong,
}

pub trait Decodable: Sized {
    fn ssz_decode(bytes: &[u8], index: usize) -> Result<Self, DecodeError>;
}

/// Decode the given bytes for the given type
///
/// The single ssz encoded value will be decoded as the given type at the
/// given index.
pub fn decode_ssz<T>(ssz_bytes: &[u8], index: usize)
    -> Result<T, DecodeError>
    where T: Decodable
{
    if index >= ssz_bytes.len() {
        return Err(DecodeError::OutOfBounds)
    }
    T::ssz_decode(ssz_bytes, index)
}

/// Decode the nth element of some ssz list.
///
/// A single ssz encoded value can be considered a list of
/// one element, so this function will work on it too.
pub fn decode_ssz_list_element<T>(ssz_bytes: &[u8], n: usize)
    -> Result<T, DecodeError>
    where T: Decodable
{
    T::ssz_decode(nth_value(ssz_bytes, n)?)
}

/// Return the nth value in some ssz encoded list.
///
/// The four-byte length prefix is not included in the return.
///
/// A single ssz encoded value can be considered a list of
/// one element, so this function will work on it too.
fn nth_value(ssz_bytes: &[u8], n: usize)
    -> Result<&[u8], DecodeError>
{
    let mut c: usize = 0;
    for i in 0..(n + 1) {
        let length = decode_length(&ssz_bytes[c..], LENGTH_BYTES)?;
        let next = c + LENGTH_BYTES + length;

        if i == n {
            return Ok(&ssz_bytes[c + LENGTH_BYTES..next]);
        } else {
            if next >= ssz_bytes.len() {
                return Err(DecodeError::OutOfBounds);
            } else {
                c = next;
            }
        }
    }
    Err(DecodeError::OutOfBounds)
}

/// Given some number of bytes, interpret the first four
/// bytes as a 32-bit big-endian integer and return the
/// result.
fn decode_length(bytes: &[u8], length_bytes: usize)
    -> Result<usize, DecodeError>
{
    if bytes.len() < length_bytes {
        return Err(DecodeError::TooShort);
    };
    let mut len: usize = 0;
    for i in 0..length_bytes {
        let offset = (length_bytes - i - 1) * 8;
        len = ((bytes[i] as usize) << offset) | len;
    };
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::encode::encode_length;

    #[test]
    fn test_ssz_decode_length() {
        let decoded = decode_length(
            &vec![0, 0, 1],
            LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 1);

        let decoded = decode_length(
            &vec![0, 1, 0],
            LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 256);

        let decoded = decode_length(
            &vec![0, 1, 255],
            LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 511);

        let decoded = decode_length(
            &vec![255, 255, 255],
            LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 16777215);
    }

    #[test]
    fn test_encode_decode_length() {
        let params: Vec<usize> = vec![
            0, 1, 2, 3, 7, 8, 16,
            2^8,  2^8  + 1,
            2^16, 2^16 + 1,
            2^24, 2^24 + 1,
            2^32,
        ];
        for i in params {
            let decoded = decode_length(
                &encode_length(i, LENGTH_BYTES),
                LENGTH_BYTES).unwrap();
            assert_eq!(i, decoded);
        }
    }

    #[test]
    fn test_ssz_nth_value() {
        let ssz = vec![0, 0, 1, 0];
        let result = nth_value(&ssz, 0).unwrap();
        assert_eq!(result, vec![0].as_slice());

        let ssz = vec![0, 0, 4, 1, 2, 3, 4];
        let result = nth_value(&ssz, 0).unwrap();
        assert_eq!(result, vec![1, 2, 3, 4].as_slice());

        let ssz = vec![0, 0, 1, 0, 0, 0, 1, 1];
        let result = nth_value(&ssz, 1).unwrap();
        assert_eq!(result, vec![1].as_slice());

        let mut ssz = vec![0, 1, 255];
        ssz.append(&mut vec![42; 511]);
        let result = nth_value(&ssz, 0).unwrap();
        assert_eq!(result, vec![42; 511].as_slice());
    }
}
