//! Provides a "legacy" version of SSZ encoding for `Option<T> where T: Encode + Decode`.
//!
//! The SSZ specification changed in 2021 to use a 1-byte union selector, instead of a 4-byte one
//! which was used in the Lighthouse database.
//!
//! Users can use the `four_byte_option_impl` macro to define a module that can be used with the
//! `#[ssz(with = "module")]`.
//!
//! ## Example
//!
//! ```rust
//! use ssz_derive::{Encode, Decode};
//! use ssz::four_byte_option_impl;
//!
//! four_byte_option_impl!(impl_for_u64, u64);
//!
//! #[derive(Encode, Decode)]
//! struct Foo {
//!     #[ssz(with = "impl_for_u64")]
//!     a: Option<u64>,
//! }
//! ```

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
    use ssz_derive::{Decode, Encode};

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

    fn round_trip<T: Encode + Decode + std::fmt::Debug + PartialEq>(items: Vec<T>) {
        for item in items {
            let encoded = &item.as_ssz_bytes();
            assert_eq!(item.ssz_bytes_len(), encoded.len());
            assert_eq!(T::from_ssz_bytes(encoded), Ok(item));
        }
    }

    #[derive(Debug, PartialEq, Encode, Decode)]
    struct TwoVariableLenOptions {
        a: u16,
        #[ssz(with = "impl_u16")]
        b: Option<u16>,
        #[ssz(with = "impl_vec_u16")]
        c: Option<Vec<u16>>,
        #[ssz(with = "impl_vec_u16")]
        d: Option<Vec<u16>>,
    }

    #[test]
    #[allow(clippy::zero_prefixed_literal)]
    fn two_variable_len_options_encoding() {
        let s = TwoVariableLenOptions {
            a: 42,
            b: None,
            c: Some(vec![0]),
            d: None,
        };

        let bytes = vec![
            //  1   2   3   4   5   6   7   8   9   10  11  12  13  14  15  16  17  18  19  20  21
            //      | option<u16>   | offset        | offset        | option<u16    | 1st list
            42, 00, 14, 00, 00, 00, 18, 00, 00, 00, 24, 00, 00, 00, 00, 00, 00, 00, 01, 00, 00, 00,
            //  23  24  25  26  27
            //      | 2nd list
            00, 00, 00, 00, 00, 00,
        ];

        assert_eq!(s.as_ssz_bytes(), bytes);
    }

    #[test]
    fn two_variable_len_options_round_trip() {
        let vec: Vec<TwoVariableLenOptions> = vec![
            TwoVariableLenOptions {
                a: 42,
                b: Some(12),
                c: Some(vec![0]),
                d: Some(vec![1]),
            },
            TwoVariableLenOptions {
                a: 42,
                b: Some(12),
                c: Some(vec![0]),
                d: None,
            },
            TwoVariableLenOptions {
                a: 42,
                b: None,
                c: Some(vec![0]),
                d: None,
            },
            TwoVariableLenOptions {
                a: 42,
                b: None,
                c: None,
                d: None,
            },
        ];

        round_trip(vec);
    }

    #[test]
    fn tuple_u8_u16() {
        let vec: Vec<(u8, u16)> = vec![
            (0, 0),
            (0, 1),
            (1, 0),
            (u8::max_value(), u16::max_value()),
            (0, u16::max_value()),
            (u8::max_value(), 0),
            (42, 12301),
        ];

        round_trip(vec);
    }

    #[test]
    fn tuple_vec_vec() {
        let vec: Vec<(u64, Vec<u8>, Vec<Vec<u16>>)> = vec![
            (0, vec![], vec![vec![]]),
            (99, vec![101], vec![vec![], vec![]]),
            (
                42,
                vec![12, 13, 14],
                vec![vec![99, 98, 97, 96], vec![42, 44, 46, 48, 50]],
            ),
        ];

        round_trip(vec);
    }
}
