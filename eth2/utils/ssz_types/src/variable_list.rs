use crate::tree_hash::vec_tree_hash_root;
use crate::Error;
use serde_derive::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut, Index, IndexMut};
use std::slice::SliceIndex;
use typenum::Unsigned;

pub use typenum;

/// Emulates a SSZ `List`.
///
/// An ordered, heap-allocated, variable-length, homogeneous collection of `T`, with no more than
/// `N` values.
///
/// This struct is backed by a Rust `Vec` but constrained such that it must be instantiated with a
/// fixed number of elements and you may not add or remove elements, only modify.
///
/// The length of this struct is fixed at the type-level using
/// [typenum](https://crates.io/crates/typenum).
///
/// ## Example
///
/// ```
/// use ssz_types::{VariableList, typenum};
///
/// let base: Vec<u64> = vec![1, 2, 3, 4];
///
/// // Create a `VariableList` from a `Vec` that has the expected length.
/// let exact: VariableList<_, typenum::U4> = VariableList::from(base.clone());
/// assert_eq!(&exact[..], &[1, 2, 3, 4]);
///
/// // Create a `VariableList` from a `Vec` that is too long and the `Vec` is truncated.
/// let short: VariableList<_, typenum::U3> = VariableList::from(base.clone());
/// assert_eq!(&short[..], &[1, 2, 3]);
///
/// // Create a `VariableList` from a `Vec` that is shorter than the maximum.
/// let mut long: VariableList<_, typenum::U5> = VariableList::from(base);
/// assert_eq!(&long[..], &[1, 2, 3, 4]);
///
/// // Push a value to if it does not exceed the maximum
/// long.push(5).unwrap();
/// assert_eq!(&long[..], &[1, 2, 3, 4, 5]);
///
/// // Push a value to if it _does_ exceed the maximum.
/// assert!(long.push(6).is_err());
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VariableList<T, N> {
    vec: Vec<T>,
    _phantom: PhantomData<N>,
}

impl<T, N: Unsigned> VariableList<T, N> {
    /// Returns `Some` if the given `vec` equals the fixed length of `Self`. Otherwise returns
    /// `None`.
    pub fn new(vec: Vec<T>) -> Result<Self, Error> {
        if vec.len() <= N::to_usize() {
            Ok(Self {
                vec,
                _phantom: PhantomData,
            })
        } else {
            Err(Error::OutOfBounds {
                i: vec.len(),
                len: Self::max_len(),
            })
        }
    }

    /// Create an empty list.
    pub fn empty() -> Self {
        Self {
            vec: vec![],
            _phantom: PhantomData,
        }
    }

    /// Returns the number of values presently in `self`.
    pub fn len(&self) -> usize {
        self.vec.len()
    }

    /// True if `self` does not contain any values.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the type-level maximum length.
    pub fn max_len() -> usize {
        N::to_usize()
    }

    /// Appends `value` to the back of `self`.
    ///
    /// Returns `Err(())` when appending `value` would exceed the maximum length.
    pub fn push(&mut self, value: T) -> Result<(), Error> {
        if self.vec.len() < Self::max_len() {
            self.vec.push(value);
            Ok(())
        } else {
            Err(Error::OutOfBounds {
                i: self.vec.len() + 1,
                len: Self::max_len(),
            })
        }
    }
}

impl<T, N: Unsigned> From<Vec<T>> for VariableList<T, N> {
    fn from(mut vec: Vec<T>) -> Self {
        vec.truncate(N::to_usize());

        Self {
            vec,
            _phantom: PhantomData,
        }
    }
}

impl<T, N: Unsigned> Into<Vec<T>> for VariableList<T, N> {
    fn into(self) -> Vec<T> {
        self.vec
    }
}

impl<T, N: Unsigned> Default for VariableList<T, N> {
    fn default() -> Self {
        Self {
            vec: Vec::default(),
            _phantom: PhantomData,
        }
    }
}

impl<T, N: Unsigned, I: SliceIndex<[T]>> Index<I> for VariableList<T, N> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&self.vec, index)
    }
}

impl<T, N: Unsigned, I: SliceIndex<[T]>> IndexMut<I> for VariableList<T, N> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut self.vec, index)
    }
}

impl<T, N: Unsigned> Deref for VariableList<T, N> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.vec[..]
    }
}

impl<T, N: Unsigned> DerefMut for VariableList<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.vec[..]
    }
}

impl<'a, T, N: Unsigned> IntoIterator for &'a VariableList<T, N> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T, N: Unsigned> tree_hash::TreeHash for VariableList<T, N>
where
    T: tree_hash::TreeHash,
{
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        let root = vec_tree_hash_root::<T, N>(&self.vec);

        tree_hash::mix_in_length(&root, self.len())
    }
}

impl<T, N: Unsigned> ssz::Encode for VariableList<T, N>
where
    T: ssz::Encode,
{
    fn is_ssz_fixed_len() -> bool {
        <Vec<T>>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <Vec<T>>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.vec.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.vec.ssz_append(buf)
    }
}

impl<T, N: Unsigned> ssz::Decode for VariableList<T, N>
where
    T: ssz::Decode,
{
    fn is_ssz_fixed_len() -> bool {
        <Vec<T>>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <Vec<T>>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let vec = <Vec<T>>::from_ssz_bytes(bytes)?;

        Self::new(vec).map_err(|e| ssz::DecodeError::BytesInvalid(format!("VariableList {:?}", e)))
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
        let fixed: Result<VariableList<u64, U4>, _> = VariableList::new(vec.clone());
        assert!(fixed.is_err());

        let vec = vec![42; 3];
        let fixed: Result<VariableList<u64, U4>, _> = VariableList::new(vec.clone());
        assert!(fixed.is_ok());

        let vec = vec![42; 4];
        let fixed: Result<VariableList<u64, U4>, _> = VariableList::new(vec.clone());
        assert!(fixed.is_ok());
    }

    #[test]
    fn indexing() {
        let vec = vec![1, 2];

        let mut fixed: VariableList<u64, U8192> = vec.clone().into();

        assert_eq!(fixed[0], 1);
        assert_eq!(&fixed[0..1], &vec[0..1]);
        assert_eq!((&fixed[..]).len(), 2);

        fixed[1] = 3;
        assert_eq!(fixed[1], 3);
    }

    #[test]
    fn length() {
        let vec = vec![42; 5];
        let fixed: VariableList<u64, U4> = VariableList::from(vec.clone());
        assert_eq!(&fixed[..], &vec[0..4]);

        let vec = vec![42; 3];
        let fixed: VariableList<u64, U4> = VariableList::from(vec.clone());
        assert_eq!(&fixed[0..3], &vec[..]);
        assert_eq!(&fixed[..], &vec![42, 42, 42][..]);

        let vec = vec![];
        let fixed: VariableList<u64, U4> = VariableList::from(vec.clone());
        assert_eq!(&fixed[..], &vec![][..]);
    }

    #[test]
    fn deref() {
        let vec = vec![0, 2, 4, 6];
        let fixed: VariableList<u64, U4> = VariableList::from(vec);

        assert_eq!(fixed.get(0), Some(&0));
        assert_eq!(fixed.get(3), Some(&6));
        assert_eq!(fixed.get(4), None);
    }

    #[test]
    fn encode() {
        let vec: VariableList<u16, U2> = vec![0; 2].into();
        assert_eq!(vec.as_ssz_bytes(), vec![0, 0, 0, 0]);
        assert_eq!(<VariableList<u16, U2> as Encode>::ssz_fixed_len(), 4);
    }

    fn round_trip<T: Encode + Decode + std::fmt::Debug + PartialEq>(item: T) {
        let encoded = &item.as_ssz_bytes();
        assert_eq!(item.ssz_bytes_len(), encoded.len());
        assert_eq!(T::from_ssz_bytes(&encoded), Ok(item));
    }

    #[test]
    fn u16_len_8() {
        round_trip::<VariableList<u16, U8>>(vec![42; 8].into());
        round_trip::<VariableList<u16, U8>>(vec![0; 8].into());
    }

    fn root_with_length(bytes: &[u8], len: usize) -> Vec<u8> {
        let root = merkle_root(bytes, 0);
        tree_hash::mix_in_length(&root, len)
    }

    #[test]
    fn tree_hash_u8() {
        let fixed: VariableList<u8, U0> = VariableList::from(vec![]);
        assert_eq!(fixed.tree_hash_root(), root_with_length(&[0; 8], 0));

        for i in 0..=1 {
            let fixed: VariableList<u8, U1> = VariableList::from(vec![0; i]);
            assert_eq!(fixed.tree_hash_root(), root_with_length(&vec![0; i], i));
        }

        for i in 0..=8 {
            let fixed: VariableList<u8, U8> = VariableList::from(vec![0; i]);
            assert_eq!(fixed.tree_hash_root(), root_with_length(&vec![0; i], i));
        }

        for i in 0..=13 {
            let fixed: VariableList<u8, U13> = VariableList::from(vec![0; i]);
            assert_eq!(fixed.tree_hash_root(), root_with_length(&vec![0; i], i));
        }

        for i in 0..=16 {
            let fixed: VariableList<u8, U16> = VariableList::from(vec![0; i]);
            assert_eq!(fixed.tree_hash_root(), root_with_length(&vec![0; i], i));
        }

        let source: Vec<u8> = (0..16).collect();
        let fixed: VariableList<u8, U16> = VariableList::from(source.clone());
        assert_eq!(fixed.tree_hash_root(), root_with_length(&source, 16));
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

    fn padded_root_with_length(bytes: &[u8], len: usize, min_nodes: usize) -> Vec<u8> {
        let root = merkle_root(bytes, min_nodes);
        tree_hash::mix_in_length(&root, len)
    }

    #[test]
    fn tree_hash_composite() {
        let a = A { a: 0, b: 1 };

        let fixed: VariableList<A, U0> = VariableList::from(vec![]);
        assert_eq!(
            fixed.tree_hash_root(),
            padded_root_with_length(&[0; 32], 0, 0),
        );

        for i in 0..=1 {
            let fixed: VariableList<A, U1> = VariableList::from(vec![a; i]);
            assert_eq!(
                fixed.tree_hash_root(),
                padded_root_with_length(&repeat(&a.tree_hash_root(), i), i, 1),
                "U1 {}",
                i
            );
        }

        for i in 0..=8 {
            let fixed: VariableList<A, U8> = VariableList::from(vec![a; i]);
            assert_eq!(
                fixed.tree_hash_root(),
                padded_root_with_length(&repeat(&a.tree_hash_root(), i), i, 8),
                "U8 {}",
                i
            );
        }

        for i in 0..=13 {
            let fixed: VariableList<A, U13> = VariableList::from(vec![a; i]);
            assert_eq!(
                fixed.tree_hash_root(),
                padded_root_with_length(&repeat(&a.tree_hash_root(), i), i, 13),
                "U13 {}",
                i
            );
        }

        for i in 0..=16 {
            let fixed: VariableList<A, U16> = VariableList::from(vec![a; i]);
            assert_eq!(
                fixed.tree_hash_root(),
                padded_root_with_length(&repeat(&a.tree_hash_root(), i), i, 16),
                "U16 {}",
                i
            );
        }
    }
}
