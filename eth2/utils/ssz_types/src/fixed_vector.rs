use crate::tree_hash::vec_tree_hash_root;
use crate::Error;
use serde_derive::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::ops::{Deref, Index, IndexMut};
use std::slice::SliceIndex;
use typenum::Unsigned;

pub use typenum;

/// Emulates a SSZ `Vector` (distinct from a Rust `Vec`).
///
/// An ordered, heap-allocated, fixed-length, homogeneous collection of `T`, with `N` values.
///
/// This struct is backed by a Rust `Vec` but constrained such that it must be instantiated with a
/// fixed number of elements and you may not add or remove elements, only modify.
///
/// The length of this struct is fixed at the type-level using
/// [typenum](https://crates.io/crates/typenum).
///
/// ## Note
///
/// Whilst it is possible with this library, SSZ declares that a `FixedVector` with a length of `0`
/// is illegal.
///
/// ## Example
///
/// ```
/// use ssz_types::{FixedVector, typenum};
///
/// let base: Vec<u64> = vec![1, 2, 3, 4];
///
/// // Create a `FixedVector` from a `Vec` that has the expected length.
/// let exact: FixedVector<_, typenum::U4> = FixedVector::from(base.clone());
/// assert_eq!(&exact[..], &[1, 2, 3, 4]);
///
/// // Create a `FixedVector` from a `Vec` that is too long and the `Vec` is truncated.
/// let short: FixedVector<_, typenum::U3> = FixedVector::from(base.clone());
/// assert_eq!(&short[..], &[1, 2, 3]);
///
/// // Create a `FixedVector` from a `Vec` that is too short and the missing values are created
/// // using `std::default::Default`.
/// let long: FixedVector<_, typenum::U5> = FixedVector::from(base);
/// assert_eq!(&long[..], &[1, 2, 3, 4, 0]);
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FixedVector<T, N> {
    vec: Vec<T>,
    _phantom: PhantomData<N>,
}

impl<T, N: Unsigned> FixedVector<T, N> {
    /// Returns `Ok` if the given `vec` equals the fixed length of `Self`. Otherwise returns
    /// `Err`.
    pub fn new(vec: Vec<T>) -> Result<Self, Error> {
        if vec.len() == Self::capacity() {
            Ok(Self {
                vec,
                _phantom: PhantomData,
            })
        } else {
            Err(Error::OutOfBounds {
                i: vec.len(),
                len: Self::capacity(),
            })
        }
    }

    /// Create a new vector filled with clones of `elem`.
    pub fn from_elem(elem: T) -> Self
    where
        T: Clone,
    {
        Self {
            vec: vec![elem; N::to_usize()],
            _phantom: PhantomData,
        }
    }

    /// Identical to `self.capacity`, returns the type-level constant length.
    ///
    /// Exists for compatibility with `Vec`.
    pub fn len(&self) -> usize {
        self.vec.len()
    }

    /// True if the type-level constant length of `self` is zero.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the type-level constant length.
    pub fn capacity() -> usize {
        N::to_usize()
    }
}

impl<T: Default, N: Unsigned> From<Vec<T>> for FixedVector<T, N> {
    fn from(mut vec: Vec<T>) -> Self {
        vec.resize_with(Self::capacity(), Default::default);

        Self {
            vec,
            _phantom: PhantomData,
        }
    }
}

impl<T, N: Unsigned> Into<Vec<T>> for FixedVector<T, N> {
    fn into(self) -> Vec<T> {
        self.vec
    }
}

impl<T, N: Unsigned> Default for FixedVector<T, N> {
    fn default() -> Self {
        Self {
            vec: Vec::default(),
            _phantom: PhantomData,
        }
    }
}

impl<T, N: Unsigned, I: SliceIndex<[T]>> Index<I> for FixedVector<T, N> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&self.vec, index)
    }
}

impl<T, N: Unsigned, I: SliceIndex<[T]>> IndexMut<I> for FixedVector<T, N> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut self.vec, index)
    }
}

impl<T, N: Unsigned> Deref for FixedVector<T, N> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.vec[..]
    }
}

impl<T, N: Unsigned> tree_hash::TreeHash for FixedVector<T, N>
where
    T: tree_hash::TreeHash,
{
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        vec_tree_hash_root::<T, N>(&self.vec)
    }
}

impl<T, N: Unsigned> ssz::Encode for FixedVector<T, N>
where
    T: ssz::Encode,
{
    fn is_ssz_fixed_len() -> bool {
        T::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        if <Self as ssz::Encode>::is_ssz_fixed_len() {
            T::ssz_fixed_len() * N::to_usize()
        } else {
            ssz::BYTES_PER_LENGTH_OFFSET
        }
    }

    fn ssz_bytes_len(&self) -> usize {
        self.vec.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        if T::is_ssz_fixed_len() {
            buf.reserve(T::ssz_fixed_len() * self.len());

            for item in &self.vec {
                item.ssz_append(buf);
            }
        } else {
            let mut encoder = ssz::SszEncoder::list(buf, self.len() * ssz::BYTES_PER_LENGTH_OFFSET);

            for item in &self.vec {
                encoder.append(item);
            }

            encoder.finalize();
        }
    }
}

impl<T, N: Unsigned> ssz::Decode for FixedVector<T, N>
where
    T: ssz::Decode + Default,
{
    fn is_ssz_fixed_len() -> bool {
        T::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        if <Self as ssz::Decode>::is_ssz_fixed_len() {
            T::ssz_fixed_len() * N::to_usize()
        } else {
            ssz::BYTES_PER_LENGTH_OFFSET
        }
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        if bytes.is_empty() {
            Err(ssz::DecodeError::InvalidByteLength {
                len: 0,
                expected: 1,
            })
        } else if T::is_ssz_fixed_len() {
            bytes
                .chunks(T::ssz_fixed_len())
                .map(|chunk| T::from_ssz_bytes(chunk))
                .collect::<Result<Vec<T>, _>>()
                .and_then(|vec| {
                    if vec.len() == N::to_usize() {
                        Ok(vec.into())
                    } else {
                        Err(ssz::DecodeError::BytesInvalid(format!(
                            "wrong number of vec elements, got: {}, expected: {}",
                            vec.len(),
                            N::to_usize()
                        )))
                    }
                })
        } else {
            ssz::decode_list_of_variable_length_items(bytes).and_then(|vec| Ok(vec.into()))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ssz::*;
    use tree_hash::{merkle_root, TreeHash};
    use tree_hash_derive::TreeHash;
    use typenum::*;

    #[test]
    fn new() {
        let vec = vec![42; 5];
        let fixed: Result<FixedVector<u64, U4>, _> = FixedVector::new(vec.clone());
        assert!(fixed.is_err());

        let vec = vec![42; 3];
        let fixed: Result<FixedVector<u64, U4>, _> = FixedVector::new(vec.clone());
        assert!(fixed.is_err());

        let vec = vec![42; 4];
        let fixed: Result<FixedVector<u64, U4>, _> = FixedVector::new(vec.clone());
        assert!(fixed.is_ok());
    }

    #[test]
    fn indexing() {
        let vec = vec![1, 2];

        let mut fixed: FixedVector<u64, U8192> = vec.clone().into();

        assert_eq!(fixed[0], 1);
        assert_eq!(&fixed[0..1], &vec[0..1]);
        assert_eq!((&fixed[..]).len(), 8192);

        fixed[1] = 3;
        assert_eq!(fixed[1], 3);
    }

    #[test]
    fn length() {
        let vec = vec![42; 5];
        let fixed: FixedVector<u64, U4> = FixedVector::from(vec.clone());
        assert_eq!(&fixed[..], &vec[0..4]);

        let vec = vec![42; 3];
        let fixed: FixedVector<u64, U4> = FixedVector::from(vec.clone());
        assert_eq!(&fixed[0..3], &vec[..]);
        assert_eq!(&fixed[..], &vec![42, 42, 42, 0][..]);

        let vec = vec![];
        let fixed: FixedVector<u64, U4> = FixedVector::from(vec.clone());
        assert_eq!(&fixed[..], &vec![0, 0, 0, 0][..]);
    }

    #[test]
    fn deref() {
        let vec = vec![0, 2, 4, 6];
        let fixed: FixedVector<u64, U4> = FixedVector::from(vec);

        assert_eq!(fixed.get(0), Some(&0));
        assert_eq!(fixed.get(3), Some(&6));
        assert_eq!(fixed.get(4), None);
    }

    #[test]
    fn ssz_encode() {
        let vec: FixedVector<u16, U2> = vec![0; 2].into();
        assert_eq!(vec.as_ssz_bytes(), vec![0, 0, 0, 0]);
        assert_eq!(<FixedVector<u16, U2> as Encode>::ssz_fixed_len(), 4);
    }

    fn ssz_round_trip<T: Encode + Decode + std::fmt::Debug + PartialEq>(item: T) {
        let encoded = &item.as_ssz_bytes();
        assert_eq!(item.ssz_bytes_len(), encoded.len());
        assert_eq!(T::from_ssz_bytes(&encoded), Ok(item));
    }

    #[test]
    fn ssz_round_trip_u16_len_8() {
        ssz_round_trip::<FixedVector<u16, U8>>(vec![42; 8].into());
        ssz_round_trip::<FixedVector<u16, U8>>(vec![0; 8].into());
    }

    #[test]
    fn tree_hash_u8() {
        let fixed: FixedVector<u8, U0> = FixedVector::from(vec![]);
        assert_eq!(fixed.tree_hash_root(), merkle_root(&[0; 8], 0));

        let fixed: FixedVector<u8, U1> = FixedVector::from(vec![0; 1]);
        assert_eq!(fixed.tree_hash_root(), merkle_root(&[0; 8], 0));

        let fixed: FixedVector<u8, U8> = FixedVector::from(vec![0; 8]);
        assert_eq!(fixed.tree_hash_root(), merkle_root(&[0; 8], 0));

        let fixed: FixedVector<u8, U16> = FixedVector::from(vec![42; 16]);
        assert_eq!(fixed.tree_hash_root(), merkle_root(&[42; 16], 0));

        let source: Vec<u8> = (0..16).collect();
        let fixed: FixedVector<u8, U16> = FixedVector::from(source.clone());
        assert_eq!(fixed.tree_hash_root(), merkle_root(&source, 0));
    }

    #[derive(Clone, Copy, TreeHash, Default)]
    struct A {
        a: u32,
        b: u32,
    }

    fn repeat(input: &[u8], n: usize) -> Vec<u8> {
        let mut output = vec![];

        for _ in 0..n {
            output.append(&mut input.to_vec());
        }

        output
    }

    #[test]
    fn tree_hash_composite() {
        let a = A { a: 0, b: 1 };

        let fixed: FixedVector<A, U0> = FixedVector::from(vec![]);
        assert_eq!(fixed.tree_hash_root(), merkle_root(&[0; 32], 0));

        let fixed: FixedVector<A, U1> = FixedVector::from(vec![a]);
        assert_eq!(fixed.tree_hash_root(), merkle_root(&a.tree_hash_root(), 0));

        let fixed: FixedVector<A, U8> = FixedVector::from(vec![a; 8]);
        assert_eq!(
            fixed.tree_hash_root(),
            merkle_root(&repeat(&a.tree_hash_root(), 8), 0)
        );

        let fixed: FixedVector<A, U13> = FixedVector::from(vec![a; 13]);
        assert_eq!(
            fixed.tree_hash_root(),
            merkle_root(&repeat(&a.tree_hash_root(), 13), 0)
        );

        let fixed: FixedVector<A, U16> = FixedVector::from(vec![a; 16]);
        assert_eq!(
            fixed.tree_hash_root(),
            merkle_root(&repeat(&a.tree_hash_root(), 16), 0)
        );
    }
}
