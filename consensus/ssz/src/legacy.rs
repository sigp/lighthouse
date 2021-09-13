use crate::*;

#[macro_export]
macro_rules! four_byte_option_impl {
    ($mod_name: ident, $type: tt) => {
        mod $mod_name {
            use super::*;

            pub mod encode {
                use super::*;
                use ssz::*;

                pub fn is_ssz_fixed_len() -> bool {
                    false
                }

                pub fn ssz_fixed_len() -> usize {
                    BYTES_PER_LENGTH_OFFSET
                }

                pub fn ssz_bytes_len(opt: &Option<$type>) -> usize {
                    if let Some(some) = opt {
                        let len = if <$type as Encode>::is_ssz_fixed_len() {
                            <$type as Encode>::ssz_fixed_len()
                        } else {
                            <$type as Encode>::ssz_bytes_len(some)
                        };
                        len + BYTES_PER_LENGTH_OFFSET
                    } else {
                        BYTES_PER_LENGTH_OFFSET
                    }
                }

                pub fn ssz_append(opt: &Option<$type>, buf: &mut Vec<u8>) {
                    match opt {
                        None => buf.extend_from_slice(&legacy::encode_four_byte_union_selector(0)),
                        Some(t) => {
                            buf.extend_from_slice(&legacy::encode_four_byte_union_selector(1));
                            t.ssz_append(buf);
                        }
                    }
                }
            }

            pub mod decode {
                use super::*;
                use ssz::*;

                pub fn is_ssz_fixed_len() -> bool {
                    false
                }

                pub fn ssz_fixed_len() -> usize {
                    BYTES_PER_LENGTH_OFFSET
                }

                pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Option<$type>, DecodeError> {
                    if bytes.len() < BYTES_PER_LENGTH_OFFSET {
                        return Err(DecodeError::InvalidByteLength {
                            len: bytes.len(),
                            expected: BYTES_PER_LENGTH_OFFSET,
                        });
                    }

                    let (index_bytes, value_bytes) = bytes.split_at(BYTES_PER_LENGTH_OFFSET);

                    let index = legacy::read_four_byte_union_selector(index_bytes)?;
                    if index == 0 {
                        Ok(None)
                    } else if index == 1 {
                        Ok(Some($type::from_ssz_bytes(value_bytes)?))
                    } else {
                        Err(DecodeError::BytesInvalid(format!(
                            "{} is not a valid union index for Option<T>",
                            index
                        )))
                    }
                }
            }
        }
    };
}

pub fn encode_four_byte_union_selector(selector: usize) -> [u8; BYTES_PER_LENGTH_OFFSET] {
    encode_length(selector)
}

pub fn read_four_byte_union_selector(bytes: &[u8]) -> Result<usize, DecodeError> {
    read_offset(bytes)
}
