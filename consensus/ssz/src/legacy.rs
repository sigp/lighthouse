use crate::*;

#[macro_export]
macro_rules! four_byte_option_impl {
    ($mod_name: ident, $type: ty) => {
        #[allow(dead_code)]
        mod $mod_name {
            use super::*;

            pub mod encode {
                use super::*;
                #[allow(unused_imports)]
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

                pub fn as_ssz_bytes(opt: &Option<$type>) -> Vec<u8> {
                    let mut buf = vec![];

                    ssz_append(opt, &mut buf);

                    buf
                }
            }

            pub mod decode {
                use super::*;
                #[allow(unused_imports)]
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
                        Ok(Some(<$type as ssz::Decode>::from_ssz_bytes(value_bytes)?))
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

#[cfg(test)]
mod test {
    use super::*;
    use crate as ssz;

    type VecU16 = Vec<u16>;

    four_byte_option_impl!(impl_u16, u16);
    four_byte_option_impl!(impl_vec_u16, VecU16);

    #[test]
    fn ssz_encode_option_u16() {
        let item = Some(65535_u16);
        let bytes = vec![1, 0, 0, 0, 255, 255];
        assert_eq!(impl_u16::encode::as_ssz_bytes(&item), bytes);
        assert_eq!(impl_u16::decode::from_ssz_bytes(&bytes).unwrap(), item);

        let item = None;
        let bytes = vec![0, 0, 0, 0];
        assert_eq!(impl_u16::encode::as_ssz_bytes(&item), bytes);
        assert_eq!(impl_u16::decode::from_ssz_bytes(&bytes).unwrap(), None);
    }

    #[test]
    fn ssz_encode_option_vec_u16() {
        let item = Some(vec![0_u16, 1]);
        let bytes = vec![1, 0, 0, 0, 0, 0, 1, 0];
        assert_eq!(impl_vec_u16::encode::as_ssz_bytes(&item), bytes);
        assert_eq!(impl_vec_u16::decode::from_ssz_bytes(&bytes).unwrap(), item);

        let item = None;
        let bytes = vec![0, 0, 0, 0];
        assert_eq!(impl_vec_u16::encode::as_ssz_bytes(&item), bytes);
        assert_eq!(impl_vec_u16::decode::from_ssz_bytes(&bytes).unwrap(), item);
    }
}
