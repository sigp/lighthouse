use super::*;

pub mod impls;

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

#[derive(Copy, Clone, Debug)]
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
            } else if offset > self.bytes.len() {
                return Err(DecodeError::OutOfBoundsByte { i: offset });
            }

            self.offsets.push(Offset {
                position: self.items.len(),
                offset,
            });

            // Push an empty slice into items; it will be replaced later.
            self.items.push(&[]);

            self.items_index += BYTES_PER_LENGTH_OFFSET;
        }

        Ok(())
    }

    fn finalize(&mut self) -> Result<(), DecodeError> {
        if !self.offsets.is_empty() {
            // Check to ensure the first offset points to the byte immediately following the
            // fixed-length bytes.
            if self.offsets[0].offset != self.items_index {
                return Err(DecodeError::OutOfBoundsByte {
                    i: self.offsets[0].offset,
                });
            }

            // Iterate through each pair of offsets, grabbing the slice between each of the offsets.
            for pair in self.offsets.windows(2) {
                let a = pair[0];
                let b = pair[1];

                self.items[a.position] = &self.bytes[a.offset..b.offset];
            }

            // Handle the last offset, pushing a slice from it's start through to the end of
            // `self.bytes`.
            if let Some(last) = self.offsets.last() {
                self.items[last.position] = &self.bytes[last.offset..]
            }
        } else {
            // If the container is fixed-length, ensure there are no excess bytes.
            if self.items_index != self.bytes.len() {
                return Err(DecodeError::InvalidByteLength {
                    len: self.bytes.len(),
                    expected: self.items_index,
                });
            }
        }

        Ok(())
    }

    pub fn build(mut self) -> Result<SszDecoder<'a>, DecodeError> {
        self.finalize()?;

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
