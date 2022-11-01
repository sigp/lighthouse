use super::*;
use core::num::NonZeroUsize;
use ethereum_types::{H160, H256, U128, U256};
use smallvec::SmallVec;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

macro_rules! impl_encodable_for_uint {
    ($type: ident, $bit_size: expr) => {
        impl Encode for $type {
            fn is_ssz_fixed_len() -> bool {
                true
            }

            fn ssz_fixed_len() -> usize {
                $bit_size / 8
            }

            fn ssz_bytes_len(&self) -> usize {
                $bit_size / 8
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                buf.extend_from_slice(&self.to_le_bytes());
            }
        }
    };
}

impl_encodable_for_uint!(u8, 8);
impl_encodable_for_uint!(u16, 16);
impl_encodable_for_uint!(u32, 32);
impl_encodable_for_uint!(u64, 64);

#[cfg(target_pointer_width = "32")]
impl_encodable_for_uint!(usize, 32);

#[cfg(target_pointer_width = "64")]
impl_encodable_for_uint!(usize, 64);

// Based on the `tuple_impls` macro from the standard library.
macro_rules! impl_encode_for_tuples {
    ($(
        $Tuple:ident {
            $(($idx:tt) -> $T:ident)+
        }
    )+) => {
        $(
            impl<$($T: Encode),+> Encode for ($($T,)+) {
                fn is_ssz_fixed_len() -> bool {
                    $(
                        <$T as Encode>::is_ssz_fixed_len() &&
                    )*
                        true
                }

                fn ssz_fixed_len() -> usize {
                    if <Self as Encode>::is_ssz_fixed_len() {
                        $(
                            <$T as Encode>::ssz_fixed_len() +
                        )*
                            0
                    } else {
                        BYTES_PER_LENGTH_OFFSET
                    }
                }

                fn ssz_bytes_len(&self) -> usize {
                    if <Self as Encode>::is_ssz_fixed_len() {
                        <Self as Encode>::ssz_fixed_len()
                    } else {
                        let mut len = 0;
                        $(
                            len += if <$T as Encode>::is_ssz_fixed_len() {
                                <$T as Encode>::ssz_fixed_len()
                            } else {
                                BYTES_PER_LENGTH_OFFSET +
                                self.$idx.ssz_bytes_len()
                            };
                        )*
                        len
                    }
                }

                fn ssz_append(&self, buf: &mut Vec<u8>) {
                    let offset = $(
                            <$T as Encode>::ssz_fixed_len() +
                        )*
                            0;

                    let mut encoder = SszEncoder::container(buf, offset);

                    $(
                        encoder.append(&self.$idx);
                    )*

                    encoder.finalize();
                }
            }
        )+
    }
}

impl_encode_for_tuples! {
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

impl<T: Encode> Encode for Option<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            Option::None => {
                let union_selector: u8 = 0u8;
                buf.push(union_selector);
            }
            Option::Some(ref inner) => {
                let union_selector: u8 = 1u8;
                buf.push(union_selector);
                inner.ssz_append(buf);
            }
        }
    }
    fn ssz_bytes_len(&self) -> usize {
        match self {
            Option::None => 1usize,
            Option::Some(ref inner) => inner
                .ssz_bytes_len()
                .checked_add(1)
                .expect("encoded length must be less than usize::max_value"),
        }
    }
}

impl<T: Encode> Encode for Arc<T> {
    fn is_ssz_fixed_len() -> bool {
        T::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        T::ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.as_ref().ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ref().ssz_bytes_len()
    }
}

// Encode transparently through references.
impl<'a, T: Encode> Encode for &'a T {
    fn is_ssz_fixed_len() -> bool {
        T::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        T::ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        T::ssz_append(self, buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        T::ssz_bytes_len(self)
    }
}

/// Compute the encoded length of a vector-like sequence of `T`.
pub fn sequence_ssz_bytes_len<I, T>(iter: I) -> usize
where
    I: Iterator<Item = T> + ExactSizeIterator,
    T: Encode,
{
    // Compute length before doing any iteration.
    let length = iter.len();
    if <T as Encode>::is_ssz_fixed_len() {
        <T as Encode>::ssz_fixed_len() * length
    } else {
        let mut len = iter.map(|item| item.ssz_bytes_len()).sum();
        len += BYTES_PER_LENGTH_OFFSET * length;
        len
    }
}

/// Encode a vector-like sequence of `T`.
pub fn sequence_ssz_append<I, T>(iter: I, buf: &mut Vec<u8>)
where
    I: Iterator<Item = T> + ExactSizeIterator,
    T: Encode,
{
    if T::is_ssz_fixed_len() {
        buf.reserve(T::ssz_fixed_len() * iter.len());

        for item in iter {
            item.ssz_append(buf);
        }
    } else {
        let mut encoder = SszEncoder::container(buf, iter.len() * BYTES_PER_LENGTH_OFFSET);

        for item in iter {
            encoder.append(&item);
        }

        encoder.finalize();
    }
}

macro_rules! impl_for_vec {
    ($type: ty) => {
        impl<T: Encode> Encode for $type {
            fn is_ssz_fixed_len() -> bool {
                false
            }

            fn ssz_bytes_len(&self) -> usize {
                sequence_ssz_bytes_len(self.iter())
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                sequence_ssz_append(self.iter(), buf)
            }
        }
    };
}

impl_for_vec!(Vec<T>);
impl_for_vec!(SmallVec<[T; 1]>);
impl_for_vec!(SmallVec<[T; 2]>);
impl_for_vec!(SmallVec<[T; 3]>);
impl_for_vec!(SmallVec<[T; 4]>);
impl_for_vec!(SmallVec<[T; 5]>);
impl_for_vec!(SmallVec<[T; 6]>);
impl_for_vec!(SmallVec<[T; 7]>);
impl_for_vec!(SmallVec<[T; 8]>);

impl<K, V> Encode for BTreeMap<K, V>
where
    K: Encode + Ord,
    V: Encode,
{
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        sequence_ssz_bytes_len(self.iter())
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        sequence_ssz_append(self.iter(), buf)
    }
}

impl<T> Encode for BTreeSet<T>
where
    T: Encode + Ord,
{
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        sequence_ssz_bytes_len(self.iter())
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        sequence_ssz_append(self.iter(), buf)
    }
}

impl Encode for bool {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        1
    }

    fn ssz_bytes_len(&self) -> usize {
        1
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(*self as u8).to_le_bytes());
    }
}

impl Encode for NonZeroUsize {
    fn is_ssz_fixed_len() -> bool {
        <usize as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <usize as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        std::mem::size_of::<usize>()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.get().ssz_append(buf)
    }
}

impl Encode for H160 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        20
    }

    fn ssz_bytes_len(&self) -> usize {
        20
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
    }
}

impl Encode for H256 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        32
    }

    fn ssz_bytes_len(&self) -> usize {
        32
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
    }
}

impl Encode for U256 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        32
    }

    fn ssz_bytes_len(&self) -> usize {
        32
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let n = <Self as Encode>::ssz_fixed_len();
        let s = buf.len();

        buf.resize(s + n, 0);
        self.to_little_endian(&mut buf[s..]);
    }
}

impl Encode for U128 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        16
    }

    fn ssz_bytes_len(&self) -> usize {
        16
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let n = <Self as Encode>::ssz_fixed_len();
        let s = buf.len();

        buf.resize(s + n, 0);
        self.to_little_endian(&mut buf[s..]);
    }
}

macro_rules! impl_encodable_for_u8_array {
    ($len: expr) => {
        impl Encode for [u8; $len] {
            fn is_ssz_fixed_len() -> bool {
                true
            }

            fn ssz_fixed_len() -> usize {
                $len
            }

            fn ssz_bytes_len(&self) -> usize {
                $len
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                buf.extend_from_slice(&self[..]);
            }
        }
    };
}

impl_encodable_for_u8_array!(4);
impl_encodable_for_u8_array!(32);
impl_encodable_for_u8_array!(48);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vec_of_u8() {
        let vec: Vec<u8> = vec![];
        assert_eq!(vec.as_ssz_bytes(), vec![]);

        let vec: Vec<u8> = vec![1];
        assert_eq!(vec.as_ssz_bytes(), vec![1]);

        let vec: Vec<u8> = vec![0, 1, 2, 3];
        assert_eq!(vec.as_ssz_bytes(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn vec_of_vec_of_u8() {
        let vec: Vec<Vec<u8>> = vec![];
        assert_eq!(vec.as_ssz_bytes(), vec![]);

        let vec: Vec<Vec<u8>> = vec![vec![]];
        assert_eq!(vec.as_ssz_bytes(), vec![4, 0, 0, 0]);

        let vec: Vec<Vec<u8>> = vec![vec![], vec![]];
        assert_eq!(vec.as_ssz_bytes(), vec![8, 0, 0, 0, 8, 0, 0, 0]);

        let vec: Vec<Vec<u8>> = vec![vec![0, 1, 2], vec![11, 22, 33]];
        assert_eq!(
            vec.as_ssz_bytes(),
            vec![8, 0, 0, 0, 11, 0, 0, 0, 0, 1, 2, 11, 22, 33]
        );
    }

    #[test]
    fn ssz_encode_u8() {
        assert_eq!(0_u8.as_ssz_bytes(), vec![0]);
        assert_eq!(1_u8.as_ssz_bytes(), vec![1]);
        assert_eq!(100_u8.as_ssz_bytes(), vec![100]);
        assert_eq!(255_u8.as_ssz_bytes(), vec![255]);
    }

    #[test]
    fn ssz_encode_u16() {
        assert_eq!(1_u16.as_ssz_bytes(), vec![1, 0]);
        assert_eq!(100_u16.as_ssz_bytes(), vec![100, 0]);
        assert_eq!((1_u16 << 8).as_ssz_bytes(), vec![0, 1]);
        assert_eq!(65535_u16.as_ssz_bytes(), vec![255, 255]);
    }

    #[test]
    fn ssz_encode_u32() {
        assert_eq!(1_u32.as_ssz_bytes(), vec![1, 0, 0, 0]);
        assert_eq!(100_u32.as_ssz_bytes(), vec![100, 0, 0, 0]);
        assert_eq!((1_u32 << 16).as_ssz_bytes(), vec![0, 0, 1, 0]);
        assert_eq!((1_u32 << 24).as_ssz_bytes(), vec![0, 0, 0, 1]);
        assert_eq!((!0_u32).as_ssz_bytes(), vec![255, 255, 255, 255]);
    }

    #[test]
    fn ssz_encode_u64() {
        assert_eq!(1_u64.as_ssz_bytes(), vec![1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            (!0_u64).as_ssz_bytes(),
            vec![255, 255, 255, 255, 255, 255, 255, 255]
        );
    }

    #[test]
    fn ssz_encode_usize() {
        assert_eq!(1_usize.as_ssz_bytes(), vec![1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            (!0_usize).as_ssz_bytes(),
            vec![255, 255, 255, 255, 255, 255, 255, 255]
        );
    }

    #[test]
    fn ssz_encode_option_u8() {
        let opt: Option<u8> = None;
        assert_eq!(opt.as_ssz_bytes(), vec![0]);
        let opt: Option<u8> = Some(2);
        assert_eq!(opt.as_ssz_bytes(), vec![1, 2]);
    }

    #[test]
    fn ssz_encode_bool() {
        assert_eq!(true.as_ssz_bytes(), vec![1]);
        assert_eq!(false.as_ssz_bytes(), vec![0]);
    }

    #[test]
    fn ssz_encode_h256() {
        assert_eq!(H256::from(&[0; 32]).as_ssz_bytes(), vec![0; 32]);
        assert_eq!(H256::from(&[1; 32]).as_ssz_bytes(), vec![1; 32]);

        let bytes = vec![
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        assert_eq!(H256::from_slice(&bytes).as_ssz_bytes(), bytes);
    }

    #[test]
    fn ssz_encode_u8_array_4() {
        assert_eq!([0, 0, 0, 0].as_ssz_bytes(), vec![0; 4]);
        assert_eq!([1, 0, 0, 0].as_ssz_bytes(), vec![1, 0, 0, 0]);
        assert_eq!([1, 2, 3, 4].as_ssz_bytes(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn tuple() {
        assert_eq!((10u8, 11u8).as_ssz_bytes(), vec![10, 11]);
        assert_eq!((10u32, 11u8).as_ssz_bytes(), vec![10, 0, 0, 0, 11]);
        assert_eq!((10u8, 11u8, 12u8).as_ssz_bytes(), vec![10, 11, 12]);
    }
}
