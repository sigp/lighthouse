use serde_derive::{Deserialize, Serialize};
use ssz::{encode_length, read_offset, Decode, DecodeError, Encode, BYTES_PER_LENGTH_OFFSET};

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FourByteSszOption<T>(pub Option<T>);

impl<T> FourByteSszOption<T> {
    pub fn none() -> Self {
        Self(None)
    }

    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }

    pub fn as_ref(&self) -> Option<&T> {
        self.0.as_ref()
    }
}

impl<T: PartialEq> PartialEq<Option<T>> for FourByteSszOption<T> {
    fn eq(&self, other: &Option<T>) -> bool {
        self.0 == *other
    }
}

impl<T> From<Option<T>> for FourByteSszOption<T> {
    fn from(opt: Option<T>) -> Self {
        Self(opt)
    }
}

impl<T: Encode> Encode for FourByteSszOption<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    #[allow(clippy::integer_arithmetic)]
    fn ssz_bytes_len(&self) -> usize {
        if let Some(some) = self.as_ref() {
            let len = if <T as Encode>::is_ssz_fixed_len() {
                <T as Encode>::ssz_fixed_len()
            } else {
                some.ssz_bytes_len()
            };
            len + BYTES_PER_LENGTH_OFFSET
        } else {
            BYTES_PER_LENGTH_OFFSET
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self.as_ref() {
            None => buf.extend_from_slice(&encode_four_byte_union_selector(0)),
            Some(t) => {
                buf.extend_from_slice(&encode_four_byte_union_selector(1));
                t.ssz_append(buf);
            }
        }
    }
}

impl<T: Decode> Decode for FourByteSszOption<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < BYTES_PER_LENGTH_OFFSET {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: BYTES_PER_LENGTH_OFFSET,
            });
        }

        let (index_bytes, value_bytes) = bytes.split_at(BYTES_PER_LENGTH_OFFSET);

        let index = read_four_byte_union_selector(index_bytes)?;
        if index == 0 {
            Ok(None.into())
        } else if index == 1 {
            Ok(Some(T::from_ssz_bytes(value_bytes)?).into())
        } else {
            Err(DecodeError::BytesInvalid(format!(
                "{} is not a valid union index for Option<T>",
                index
            )))
        }
    }
}

pub fn encode_four_byte_union_selector(selector: usize) -> [u8; BYTES_PER_LENGTH_OFFSET] {
    encode_length(selector)
}

pub fn read_four_byte_union_selector(bytes: &[u8]) -> Result<usize, DecodeError> {
    read_offset(bytes)
}
