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
    fn ssz_decode(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError>;
}

/// Decode the given bytes for the given type
///
/// The single ssz encoded value will be decoded as the given type at the
/// given index.
pub fn decode_ssz<T>(ssz_bytes: &[u8], index: usize)
    -> Result<(T, usize), DecodeError>
    where T: Decodable
{
    if index >= ssz_bytes.len() {
        return Err(DecodeError::OutOfBounds)
    }
    T::ssz_decode(ssz_bytes, index)
}

/// Decode a vector (list) of encoded bytes.
///
/// Each element in the list will be decoded and placed into the vector.
pub fn decode_ssz_list<T>(ssz_bytes: &[u8], index: usize)
    -> Result<(Vec<T>, usize), DecodeError>
    where T: Decodable
{

    if index + LENGTH_BYTES > ssz_bytes.len() {
        return Err(DecodeError::OutOfBounds);
    };

    // get the length
    let mut serialized_length = match decode_length(ssz_bytes, LENGTH_BYTES) {
        Err(v) => return Err(v),
        Ok(v) => v,
    };

    let final_len: usize = index + LENGTH_BYTES + serialized_length;

    if final_len > ssz_bytes.len() {
        return Err(DecodeError::OutOfBounds);
    };

    let mut tmp_index = index + LENGTH_BYTES;
    let mut res_vec: Vec<T> = Vec::new();

    while tmp_index < final_len {
        match T::ssz_decode(ssz_bytes, tmp_index) {
            Err(v) => return Err(v),
            Ok(v) => {
                tmp_index = v.1;
                res_vec.push(v.0);
            },
        };

    };

    Ok((res_vec, final_len))
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
            &vec![0, 0, 0, 1],
            LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 1);

        let decoded = decode_length(
            &vec![0, 0, 1, 0],
            LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 256);

        let decoded = decode_length(
            &vec![0, 0, 1, 255],
            LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 511);

        let decoded = decode_length(
            &vec![255, 255, 255, 255],
            LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 4294967295);
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
}
