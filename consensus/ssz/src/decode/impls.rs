use super::*;
use core::num::NonZeroUsize;
use ethereum_types::{H256, U128, U256};
use smallvec::SmallVec;
use std::sync::Arc;

macro_rules! impl_decodable_for_uint {
    ($type: ident, $bit_size: expr) => {
        impl Decode for $type {
            fn is_ssz_fixed_len() -> bool {
                true
            }

            fn ssz_fixed_len() -> usize {
                $bit_size / 8
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
                let len = bytes.len();
                let expected = <Self as Decode>::ssz_fixed_len();

                if len != expected {
                    Err(DecodeError::InvalidByteLength { len, expected })
                } else {
                    let mut array: [u8; $bit_size / 8] = std::default::Default::default();
                    array.clone_from_slice(bytes);

                    Ok(Self::from_le_bytes(array))
                }
            }
        }
    };
}

impl_decodable_for_uint!(u8, 8);
impl_decodable_for_uint!(u16, 16);
impl_decodable_for_uint!(u32, 32);
impl_decodable_for_uint!(u64, 64);

#[cfg(target_pointer_width = "32")]
impl_decodable_for_uint!(usize, 32);

#[cfg(target_pointer_width = "64")]
impl_decodable_for_uint!(usize, 64);

macro_rules! impl_decode_for_tuples {
    ($(
        $Tuple:ident {
            $(($idx:tt) -> $T:ident)+
        }
    )+) => {
        $(
            impl<$($T: Decode),+> Decode for ($($T,)+) {
                fn is_ssz_fixed_len() -> bool {
                    $(
                        <$T as Decode>::is_ssz_fixed_len() &&
                    )*
                        true
                }

                fn ssz_fixed_len() -> usize {
                    if <Self as Decode>::is_ssz_fixed_len() {
                        $(
                            <$T as Decode>::ssz_fixed_len() +
                        )*
                            0
                    } else {
                        BYTES_PER_LENGTH_OFFSET
                    }
                }

                fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
                    let mut builder = SszDecoderBuilder::new(bytes);

                    $(
                        builder.register_type::<$T>()?;
                    )*

                    let mut decoder = builder.build()?;

                    Ok(($(
                            decoder.decode_next::<$T>()?,
                        )*
                    ))
                }
            }
        )+
    }
}

impl_decode_for_tuples! {
    Tuple2 {
        (0) -> A
        (1) -> B
    }
    Tuple3 {
        (0) -> A
        (1) -> B
        (2) -> C
    }
    Tuple4 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
    }
    Tuple5 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
    }
    Tuple6 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
    }
    Tuple7 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
    }
    Tuple8 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
    }
    Tuple9 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
        (8) -> I
    }
    Tuple10 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
        (8) -> I
        (9) -> J
    }
    Tuple11 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
        (8) -> I
        (9) -> J
        (10) -> K
    }
    Tuple12 {
        (0) -> A
        (1) -> B
        (2) -> C
        (3) -> D
        (4) -> E
        (5) -> F
        (6) -> G
        (7) -> H
        (8) -> I
        (9) -> J
        (10) -> K
        (11) -> L
    }
}

impl Decode for bool {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        1
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let len = bytes.len();
        let expected = <Self as Decode>::ssz_fixed_len();

        if len != expected {
            Err(DecodeError::InvalidByteLength { len, expected })
        } else {
            match bytes[0] {
                0b0000_0000 => Ok(false),
                0b0000_0001 => Ok(true),
                _ => Err(DecodeError::BytesInvalid(format!(
                    "Out-of-range for boolean: {}",
                    bytes[0]
                ))),
            }
        }
    }
}

impl Decode for NonZeroUsize {
    fn is_ssz_fixed_len() -> bool {
        <usize as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <usize as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let x = usize::from_ssz_bytes(bytes)?;

        if x == 0 {
            Err(DecodeError::BytesInvalid(
                "NonZeroUsize cannot be zero.".to_string(),
            ))
        } else {
            // `unwrap` is safe here as `NonZeroUsize::new()` succeeds if `x > 0` and this path
            // never executes when `x == 0`.
            Ok(NonZeroUsize::new(x).unwrap())
        }
    }
}

impl<T: Decode> Decode for Arc<T> {
    fn is_ssz_fixed_len() -> bool {
        T::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        T::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        T::from_ssz_bytes(bytes).map(Arc::new)
    }
}

impl Decode for H256 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        32
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let len = bytes.len();
        let expected = <Self as Decode>::ssz_fixed_len();

        if len != expected {
            Err(DecodeError::InvalidByteLength { len, expected })
        } else {
            Ok(H256::from_slice(bytes))
        }
    }
}

impl Decode for U256 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        32
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let len = bytes.len();
        let expected = <Self as Decode>::ssz_fixed_len();

        if len != expected {
            Err(DecodeError::InvalidByteLength { len, expected })
        } else {
            Ok(U256::from_little_endian(bytes))
        }
    }
}

impl Decode for U128 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        16
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let len = bytes.len();
        let expected = <Self as Decode>::ssz_fixed_len();

        if len != expected {
            Err(DecodeError::InvalidByteLength { len, expected })
        } else {
            Ok(U128::from_little_endian(bytes))
        }
    }
}

macro_rules! impl_decodable_for_u8_array {
    ($len: expr) => {
        impl Decode for [u8; $len] {
            fn is_ssz_fixed_len() -> bool {
                true
            }

            fn ssz_fixed_len() -> usize {
                $len
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
                let len = bytes.len();
                let expected = <Self as Decode>::ssz_fixed_len();

                if len != expected {
                    Err(DecodeError::InvalidByteLength { len, expected })
                } else {
                    let mut array: [u8; $len] = [0; $len];
                    array.copy_from_slice(bytes);

                    Ok(array)
                }
            }
        }
    };
}

impl_decodable_for_u8_array!(4);
impl_decodable_for_u8_array!(32);

macro_rules! impl_for_vec {
    ($type: ty, $max_len: expr) => {
        impl<T: Decode> Decode for $type {
            fn is_ssz_fixed_len() -> bool {
                false
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
                if bytes.is_empty() {
                    Ok(vec![].into())
                } else if T::is_ssz_fixed_len() {
                    bytes
                        .chunks(T::ssz_fixed_len())
                        .map(|chunk| T::from_ssz_bytes(chunk))
                        .collect()
                } else {
                    decode_list_of_variable_length_items(bytes, $max_len).map(|vec| vec.into())
                }
            }
        }
    };
}

impl_for_vec!(Vec<T>, None);
impl_for_vec!(SmallVec<[T; 1]>, Some(1));
impl_for_vec!(SmallVec<[T; 2]>, Some(2));
impl_for_vec!(SmallVec<[T; 3]>, Some(3));
impl_for_vec!(SmallVec<[T; 4]>, Some(4));
impl_for_vec!(SmallVec<[T; 5]>, Some(5));
impl_for_vec!(SmallVec<[T; 6]>, Some(6));
impl_for_vec!(SmallVec<[T; 7]>, Some(7));
impl_for_vec!(SmallVec<[T; 8]>, Some(8));

/// Decodes `bytes` as if it were a list of variable-length items.
///
/// The `ssz::SszDecoder` can also perform this functionality, however it it significantly faster
/// as it is optimized to read same-typed items whilst `ssz::SszDecoder` supports reading items of
/// differing types.
pub fn decode_list_of_variable_length_items<T: Decode>(
    bytes: &[u8],
    max_len: Option<usize>,
) -> Result<Vec<T>, DecodeError> {
    if bytes.is_empty() {
        return Ok(vec![]);
    }

    let first_offset = read_offset(bytes)?;
    sanitize_offset(first_offset, None, bytes.len(), Some(first_offset))?;

    if first_offset % BYTES_PER_LENGTH_OFFSET != 0 || first_offset < BYTES_PER_LENGTH_OFFSET {
        return Err(DecodeError::InvalidListFixedBytesLen(first_offset));
    }

    let num_items = first_offset / BYTES_PER_LENGTH_OFFSET;

    if max_len.map_or(false, |max| num_items > max) {
        return Err(DecodeError::BytesInvalid(format!(
            "Variable length list of {} items exceeds maximum of {:?}",
            num_items, max_len
        )));
    }

    // Only initialize the vec with a capacity if a maximum length is provided.
    //
    // We assume that if a max length is provided then the application is able to handle an
    // allocation of this size.
    let mut values = if max_len.is_some() {
        Vec::with_capacity(num_items)
    } else {
        vec![]
    };

    let mut offset = first_offset;
    for i in 1..=num_items {
        let slice_option = if i == num_items {
            bytes.get(offset..)
        } else {
            let start = offset;

            let next_offset = read_offset(&bytes[(i * BYTES_PER_LENGTH_OFFSET)..])?;
            offset = sanitize_offset(next_offset, Some(offset), bytes.len(), Some(first_offset))?;

            bytes.get(start..offset)
        };

        let slice = slice_option.ok_or(DecodeError::OutOfBoundsByte { i: offset })?;

        values.push(T::from_ssz_bytes(slice)?);
    }

    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: decoding of valid bytes is generally tested "indirectly" in the `/tests` dir, by
    // encoding then decoding the element.

    #[test]
    fn invalid_u8_array_4() {
        assert_eq!(
            <[u8; 4]>::from_ssz_bytes(&[0; 3]),
            Err(DecodeError::InvalidByteLength {
                len: 3,
                expected: 4
            })
        );

        assert_eq!(
            <[u8; 4]>::from_ssz_bytes(&[0; 5]),
            Err(DecodeError::InvalidByteLength {
                len: 5,
                expected: 4
            })
        );
    }

    #[test]
    fn invalid_bool() {
        assert_eq!(
            bool::from_ssz_bytes(&[0; 2]),
            Err(DecodeError::InvalidByteLength {
                len: 2,
                expected: 1
            })
        );

        assert_eq!(
            bool::from_ssz_bytes(&[]),
            Err(DecodeError::InvalidByteLength {
                len: 0,
                expected: 1
            })
        );

        if let Err(DecodeError::BytesInvalid(_)) = bool::from_ssz_bytes(&[2]) {
            // Success.
        } else {
            panic!("Did not return error on invalid bool val")
        }
    }

    #[test]
    fn invalid_h256() {
        assert_eq!(
            H256::from_ssz_bytes(&[0; 33]),
            Err(DecodeError::InvalidByteLength {
                len: 33,
                expected: 32
            })
        );

        assert_eq!(
            H256::from_ssz_bytes(&[0; 31]),
            Err(DecodeError::InvalidByteLength {
                len: 31,
                expected: 32
            })
        );
    }

    #[test]
    fn empty_list() {
        let vec: Vec<Vec<u16>> = vec![];
        let bytes = vec.as_ssz_bytes();
        assert!(bytes.is_empty());
        assert_eq!(Vec::from_ssz_bytes(&bytes), Ok(vec),);
    }

    #[test]
    fn first_length_points_backwards() {
        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[0, 0, 0, 0]),
            Err(DecodeError::InvalidListFixedBytesLen(0))
        );

        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[1, 0, 0, 0]),
            Err(DecodeError::InvalidListFixedBytesLen(1))
        );

        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[2, 0, 0, 0]),
            Err(DecodeError::InvalidListFixedBytesLen(2))
        );

        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[3, 0, 0, 0]),
            Err(DecodeError::InvalidListFixedBytesLen(3))
        );
    }

    #[test]
    fn lengths_are_decreasing() {
        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[12, 0, 0, 0, 14, 0, 0, 0, 12, 0, 0, 0, 1, 0, 1, 0]),
            Err(DecodeError::OffsetsAreDecreasing(12))
        );
    }

    #[test]
    fn awkward_fixed_length_portion() {
        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[10, 0, 0, 0, 10, 0, 0, 0, 0, 0]),
            Err(DecodeError::InvalidListFixedBytesLen(10))
        );
    }

    #[test]
    fn length_out_of_bounds() {
        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[5, 0, 0, 0]),
            Err(DecodeError::OffsetOutOfBounds(5))
        );
        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[8, 0, 0, 0, 9, 0, 0, 0]),
            Err(DecodeError::OffsetOutOfBounds(9))
        );
        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[8, 0, 0, 0, 16, 0, 0, 0]),
            Err(DecodeError::OffsetOutOfBounds(16))
        );
    }

    #[test]
    fn vec_of_vec_of_u16() {
        assert_eq!(
            <Vec<Vec<u16>>>::from_ssz_bytes(&[4, 0, 0, 0]),
            Ok(vec![vec![]])
        );

        assert_eq!(
            <Vec<u16>>::from_ssz_bytes(&[0, 0, 1, 0, 2, 0, 3, 0]),
            Ok(vec![0, 1, 2, 3])
        );
        assert_eq!(<u16>::from_ssz_bytes(&[16, 0]), Ok(16));
        assert_eq!(<u16>::from_ssz_bytes(&[0, 1]), Ok(256));
        assert_eq!(<u16>::from_ssz_bytes(&[255, 255]), Ok(65535));

        assert_eq!(
            <u16>::from_ssz_bytes(&[255]),
            Err(DecodeError::InvalidByteLength {
                len: 1,
                expected: 2
            })
        );

        assert_eq!(
            <u16>::from_ssz_bytes(&[]),
            Err(DecodeError::InvalidByteLength {
                len: 0,
                expected: 2
            })
        );

        assert_eq!(
            <u16>::from_ssz_bytes(&[0, 1, 2]),
            Err(DecodeError::InvalidByteLength {
                len: 3,
                expected: 2
            })
        );
    }

    #[test]
    fn vec_of_u16() {
        assert_eq!(<Vec<u16>>::from_ssz_bytes(&[0, 0, 0, 0]), Ok(vec![0, 0]));
        assert_eq!(
            <Vec<u16>>::from_ssz_bytes(&[0, 0, 1, 0, 2, 0, 3, 0]),
            Ok(vec![0, 1, 2, 3])
        );
        assert_eq!(<u16>::from_ssz_bytes(&[16, 0]), Ok(16));
        assert_eq!(<u16>::from_ssz_bytes(&[0, 1]), Ok(256));
        assert_eq!(<u16>::from_ssz_bytes(&[255, 255]), Ok(65535));

        assert_eq!(
            <u16>::from_ssz_bytes(&[255]),
            Err(DecodeError::InvalidByteLength {
                len: 1,
                expected: 2
            })
        );

        assert_eq!(
            <u16>::from_ssz_bytes(&[]),
            Err(DecodeError::InvalidByteLength {
                len: 0,
                expected: 2
            })
        );

        assert_eq!(
            <u16>::from_ssz_bytes(&[0, 1, 2]),
            Err(DecodeError::InvalidByteLength {
                len: 3,
                expected: 2
            })
        );
    }

    #[test]
    fn u16() {
        assert_eq!(<u16>::from_ssz_bytes(&[0, 0]), Ok(0));
        assert_eq!(<u16>::from_ssz_bytes(&[16, 0]), Ok(16));
        assert_eq!(<u16>::from_ssz_bytes(&[0, 1]), Ok(256));
        assert_eq!(<u16>::from_ssz_bytes(&[255, 255]), Ok(65535));

        assert_eq!(
            <u16>::from_ssz_bytes(&[255]),
            Err(DecodeError::InvalidByteLength {
                len: 1,
                expected: 2
            })
        );

        assert_eq!(
            <u16>::from_ssz_bytes(&[]),
            Err(DecodeError::InvalidByteLength {
                len: 0,
                expected: 2
            })
        );

        assert_eq!(
            <u16>::from_ssz_bytes(&[0, 1, 2]),
            Err(DecodeError::InvalidByteLength {
                len: 3,
                expected: 2
            })
        );
    }

    #[test]
    fn tuple() {
        assert_eq!(<(u16, u16)>::from_ssz_bytes(&[0, 0, 0, 0]), Ok((0, 0)));
        assert_eq!(<(u16, u16)>::from_ssz_bytes(&[16, 0, 17, 0]), Ok((16, 17)));
        assert_eq!(<(u16, u16)>::from_ssz_bytes(&[0, 1, 2, 0]), Ok((256, 2)));
        assert_eq!(
            <(u16, u16)>::from_ssz_bytes(&[255, 255, 0, 0]),
            Ok((65535, 0))
        );
    }
}
