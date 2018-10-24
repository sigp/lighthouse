use super::{
    LENGTH_BYTES,
};

#[derive(Debug, PartialEq)]
pub enum DecodeError {
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
        return Err(DecodeError::TooShort)
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
        return Err(DecodeError::TooShort);
    };

    // get the length
    let serialized_length = match decode_length(ssz_bytes, index, LENGTH_BYTES) {
        Err(v) => return Err(v),
        Ok(v) => v,
    };

    let final_len: usize = index + LENGTH_BYTES + serialized_length;

    if final_len > ssz_bytes.len() {
        return Err(DecodeError::TooShort);
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
pub fn decode_length(bytes: &[u8], index: usize, length_bytes: usize)
    -> Result<usize, DecodeError>
{
    if bytes.len() < index + length_bytes {
        return Err(DecodeError::TooShort);
    };
    let mut len: usize = 0;
    for (i, byte) in bytes.iter().enumerate().take(index+length_bytes).skip(index) {
        let offset = (index+length_bytes - i - 1) * 8;
        len |= (*byte as usize) << offset;
    }
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
            0,
            LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 1);

        let decoded = decode_length(
            &vec![0, 0, 1, 0],
            0,
            LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 256);

        let decoded = decode_length(
            &vec![0, 0, 1, 255],
            0,
            LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 511);

        let decoded = decode_length(
            &vec![255, 255, 255, 255],
            0,
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
                0,
                LENGTH_BYTES).unwrap();
            assert_eq!(i, decoded);
        }
    }

    #[test]
    fn test_decode_ssz_list() {
        // u16
        let v: Vec<u16> = vec![10, 10, 10, 10];
        let decoded: (Vec<u16>, usize) = decode_ssz_list(
            &vec![0, 0, 0, 8, 0, 10, 0, 10, 0, 10, 0, 10],
            0
        ).unwrap();

        assert_eq!(decoded.0, v);
        assert_eq!(decoded.1, 12);

        // u32
        let v: Vec<u32> = vec![10, 10, 10, 10];
        let decoded: (Vec<u32>, usize) = decode_ssz_list(
            &vec![
                0, 0, 0, 16,
                0, 0, 0, 10, 0, 0, 0, 10, 0, 0, 0, 10, 0, 0, 0, 10
            ],
            0
        ).unwrap();
        assert_eq!(decoded.0, v);
        assert_eq!(decoded.1, 20);


        // u64
        let v: Vec<u64> = vec![10,10,10,10];
        let decoded: (Vec<u64>, usize) = decode_ssz_list(
            &vec![0, 0, 0, 32,
                0, 0, 0, 0, 0, 0, 0, 10,
                0, 0, 0, 0, 0, 0, 0, 10,
                0, 0, 0, 0, 0, 0, 0, 10,
                0, 0, 0, 0, 0, 0, 0, 10,
            ],
            0
        ).unwrap();
        assert_eq!(decoded.0, v);
        assert_eq!(decoded.1, 36);

        // Check that it can accept index
        let v: Vec<usize> = vec![15,15,15,15];
        let decoded: (Vec<usize>, usize) = decode_ssz_list(
            &vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                0, 0, 0, 32,
                0, 0, 0, 0, 0, 0, 0, 15,
                0, 0, 0, 0, 0, 0, 0, 15,
                0, 0, 0, 0, 0, 0, 0, 15,
                0, 0, 0, 0, 0, 0, 0, 15,
            ],
            10
        ).unwrap();
        assert_eq!(decoded.0, v);
        assert_eq!(decoded.1, 46);

        // Check that length > bytes throws error
        let decoded: Result<(Vec<usize>, usize), DecodeError> = decode_ssz_list(
            &vec![0, 0, 0, 32,
                0, 0, 0, 0, 0, 0, 0, 15,
            ],
            0
        );
        assert_eq!(decoded, Err(DecodeError::TooShort));

        // Check that incorrect index throws error
        let decoded: Result<(Vec<usize>, usize), DecodeError> = decode_ssz_list(
            &vec![
                0, 0, 0, 0, 0, 0, 0, 15,
            ],
            16
        );
        assert_eq!(decoded, Err(DecodeError::TooShort));
    }
}
