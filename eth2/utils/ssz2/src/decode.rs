use super::*;

mod impls;

#[derive(Debug, PartialEq)]
pub enum DecodeError {
    /// The bytes supplied were too short to be decoded into the specified type.
    InvalidByteLength { len: usize, expected: usize },
    /// The given bytes were too short to be read as a length prefix.
    InvalidLengthPrefix { len: usize, expected: usize },
    /// A length offset pointed to a byte that was out-of-bounds (OOB).
    ///
    /// A bytes may be OOB for the following reasons:
    ///
    /// - It is `>= bytes.len()`.
    /// - When decoding variable length items, the 1st offset points "backwards" into the fixed
    /// length items (i.e., `length[0] < BYTES_PER_LENGTH_OFFSET`).
    /// - When decoding variable-length items, the `n`'th offset was less than the `n-1`'th offset.
    OutOfBoundsByte { i: usize },
    /// The given bytes were invalid for some application-level reason.
    BytesInvalid(String),
}

pub trait Decodable: Sized {
    fn is_ssz_fixed_len() -> bool;

    /// The number of bytes this object occupies in the fixed-length portion of the SSZ bytes.
    ///
    /// By default, this is set to `BYTES_PER_LENGTH_OFFSET` which is suitable for variable length
    /// objects, but not fixed-length objects. Fixed-length objects _must_ return a value which
    /// represents their length.
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError>;
}

/*

/// Decode the given bytes for the given type
///
/// The single ssz encoded value/container/list will be decoded as the given type,
/// by recursively calling `ssz_decode`.
/// Check on totality for underflowing the length of bytes and overflow checks done per container
pub fn decode<T>(ssz_bytes: &[u8]) -> Result<(T), DecodeError>
where
    T: Decodable,
{
    let (decoded, i): (T, usize) = match T::ssz_decode(ssz_bytes, 0) {
        Err(e) => return Err(e),
        Ok(v) => v,
    };

    if i < ssz_bytes.len() {
        return Err(DecodeError::TooLong);
    }

    Ok(decoded)
}

/// Decode a vector (list) of encoded bytes.
///
/// Each element in the list will be decoded and placed into the vector.
pub fn decode_ssz_list<T>(ssz_bytes: &[u8], index: usize) -> Result<(Vec<T>, usize), DecodeError>
where
    T: Decodable,
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
            }
        };
    }

    Ok((res_vec, final_len))
}

/// Given some number of bytes, interpret the first four
/// bytes as a 32-bit little-endian integer and return the
/// result.
pub fn decode_length(
    bytes: &[u8],
    index: usize,
    length_bytes: usize,
) -> Result<usize, DecodeError> {
    if bytes.len() < index + length_bytes {
        return Err(DecodeError::TooShort);
    };
    let mut len: usize = 0;
    for (i, byte) in bytes
        .iter()
        .enumerate()
        .take(index + length_bytes)
        .skip(index)
    {
        let offset = (i - index) * 8;
        len |= (*byte as usize) << offset;
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::super::encode::*;
    use super::*;

    #[test]
    fn test_ssz_decode_length() {
        let decoded = decode_length(&vec![1, 0, 0, 0], 0, LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 1);

        let decoded = decode_length(&vec![0, 1, 0, 0], 0, LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 256);

        let decoded = decode_length(&vec![255, 1, 0, 0], 0, LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 511);

        let decoded = decode_length(&vec![255, 255, 255, 255], 0, LENGTH_BYTES);
        assert_eq!(decoded.unwrap(), 4294967295);
    }

    #[test]
    fn test_encode_decode_length() {
        let params: Vec<usize> = vec![
            0,
            1,
            2,
            3,
            7,
            8,
            16,
            2 ^ 8,
            2 ^ 8 + 1,
            2 ^ 16,
            2 ^ 16 + 1,
            2 ^ 24,
            2 ^ 24 + 1,
            2 ^ 32,
        ];
        for i in params {
            let decoded = decode_length(&encode_length(i, LENGTH_BYTES), 0, LENGTH_BYTES).unwrap();
            assert_eq!(i, decoded);
        }
    }

    #[test]
    fn test_encode_decode_ssz_list() {
        let test_vec: Vec<u16> = vec![256; 12];
        let mut stream = SszStream::new();
        stream.append_vec(&test_vec);
        let ssz = stream.drain();

        // u16
        let decoded: (Vec<u16>, usize) = decode_ssz_list(&ssz, 0).unwrap();

        assert_eq!(decoded.0, test_vec);
        assert_eq!(decoded.1, LENGTH_BYTES + (12 * 2));
    }

    #[test]
    fn test_decode_ssz_list() {
        // u16
        let v: Vec<u16> = vec![10, 10, 10, 10];
        let decoded: (Vec<u16>, usize) =
            decode_ssz_list(&vec![8, 0, 0, 0, 10, 0, 10, 0, 10, 0, 10, 0], 0).unwrap();

        assert_eq!(decoded.0, v);
        assert_eq!(decoded.1, LENGTH_BYTES + (4 * 2));

        // u32
        let v: Vec<u32> = vec![10, 10, 10, 10];
        let decoded: (Vec<u32>, usize) = decode_ssz_list(
            &vec![
                16, 0, 0, 0, 10, 0, 0, 0, 10, 0, 0, 0, 10, 0, 0, 0, 10, 0, 0, 00,
            ],
            0,
        )
        .unwrap();
        assert_eq!(decoded.0, v);
        assert_eq!(decoded.1, 20);

        // u64
        let v: Vec<u64> = vec![10, 10, 10, 10];
        let decoded: (Vec<u64>, usize) = decode_ssz_list(
            &vec![
                32, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0,
                0, 0, 10, 0, 0, 0, 0, 0, 0, 0,
            ],
            0,
        )
        .unwrap();
        assert_eq!(decoded.0, v);
        assert_eq!(decoded.1, LENGTH_BYTES + (8 * 4));

        // Check that it can accept index
        let v: Vec<usize> = vec![15, 15, 15, 15];
        let offset = 10;
        let decoded: (Vec<usize>, usize) = decode_ssz_list(
            &vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 32, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0,
                0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0,
            ],
            offset,
        )
        .unwrap();
        assert_eq!(decoded.0, v);
        assert_eq!(decoded.1, offset + LENGTH_BYTES + (8 * 4));

        // Check that length > bytes throws error
        let decoded: Result<(Vec<usize>, usize), DecodeError> =
            decode_ssz_list(&vec![32, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0], 0);
        assert_eq!(decoded, Err(DecodeError::TooShort));

        // Check that incorrect index throws error
        let decoded: Result<(Vec<usize>, usize), DecodeError> =
            decode_ssz_list(&vec![15, 0, 0, 0, 0, 0, 0, 0], 16);
        assert_eq!(decoded, Err(DecodeError::TooShort));
    }
}
*/
