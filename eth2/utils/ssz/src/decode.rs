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

#[derive(Copy, Clone)]
pub struct Offset {
    position: usize,
    offset: usize,
}

pub struct SszDecoderBuilder<'a> {
    bytes: &'a [u8],
    items: Vec<&'a [u8]>,
    offsets: Vec<Offset>,
    items_index: usize,
}

impl<'a> SszDecoderBuilder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            items: vec![],
            offsets: vec![],
            items_index: 0,
        }
    }

    pub fn register_type<T: Decodable>(&mut self) -> Result<(), DecodeError> {
        if T::is_ssz_fixed_len() {
            let start = self.items_index;
            self.items_index += T::ssz_fixed_len();

            let slice = self.bytes.get(start..self.items_index).ok_or_else(|| {
                DecodeError::InvalidByteLength {
                    len: self.bytes.len(),
                    expected: self.items_index,
                }
            })?;

            self.items.push(slice);
        } else {
            let offset = read_offset(&self.bytes[self.items_index..])?;

            let previous_offset = self
                .offsets
                .last()
                .and_then(|o| Some(o.offset))
                .unwrap_or_else(|| BYTES_PER_LENGTH_OFFSET);

            if previous_offset > offset {
                return Err(DecodeError::OutOfBoundsByte { i: offset });
            } else if offset >= self.bytes.len() {
                return Err(DecodeError::OutOfBoundsByte { i: offset });
            }

            self.offsets.push(Offset {
                position: self.items.len(),
                offset,
            });

            self.items_index += BYTES_PER_LENGTH_OFFSET;
        }

        Ok(())
    }

    fn apply_offsets(&mut self) -> Result<(), DecodeError> {
        if !self.offsets.is_empty() {
            let mut insertions = 0;
            let mut running_offset = self.offsets[0].offset;

            for i in 1..=self.offsets.len() {
                let (slice_option, position) = if i == self.offsets.len() {
                    (self.bytes.get(running_offset..), self.offsets.len())
                } else {
                    let offset = self.offsets[i];
                    let start = running_offset;
                    running_offset = offset.offset;

                    (self.bytes.get(start..running_offset), offset.position)
                };

                let slice = slice_option
                    .ok_or_else(|| DecodeError::OutOfBoundsByte { i: running_offset })?;

                self.items.insert(position + insertions, slice);
                insertions += 1;
            }
        }

        Ok(())
    }

    pub fn build(mut self) -> Result<SszDecoder<'a>, DecodeError> {
        self.apply_offsets()?;

        Ok(SszDecoder { items: self.items })
    }
}

pub struct SszDecoder<'a> {
    items: Vec<&'a [u8]>,
}

impl<'a> SszDecoder<'a> {
    /// Decodes the next item.
    ///
    /// # Panics
    ///
    /// Panics when attempting to decode more items than actually exist.
    pub fn decode_next<T: Decodable>(&mut self) -> Result<T, DecodeError> {
        T::from_ssz_bytes(self.items.remove(0))
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
fn decode_offset(bytes: &[u8]) -> Result<usize, DecodeError> {
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
