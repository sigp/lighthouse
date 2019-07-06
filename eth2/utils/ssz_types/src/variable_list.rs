use crate::Error;
use serde_derive::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::ops::{Deref, Index, IndexMut};
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
            Err(Error::InvalidLength {
                i: vec.len(),
                len: Self::max_len(),
            })
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
            Ok(self.vec.push(value))
        } else {
            Err(Error::InvalidLength {
                i: self.vec.len() + 1,
                len: Self::max_len(),
            })
        }
    }
}

impl<T: Default, N: Unsigned> From<Vec<T>> for VariableList<T, N> {
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

#[cfg(test)]
mod test {
    use super::*;
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
}

/*
impl<T, N: Unsigned> tree_hash::TreeHash for VariableList<T, N>
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
        tree_hash::impls::vec_tree_hash_root(&self.vec)
    }
}

impl<T, N: Unsigned> cached_tree_hash::CachedTreeHash for VariableList<T, N>
where
    T: cached_tree_hash::CachedTreeHash + tree_hash::TreeHash,
{
    fn new_tree_hash_cache(
        &self,
        depth: usize,
    ) -> Result<cached_tree_hash::TreeHashCache, cached_tree_hash::Error> {
        let (cache, _overlay) = cached_tree_hash::vec::new_tree_hash_cache(&self.vec, depth)?;

        Ok(cache)
    }

    fn tree_hash_cache_schema(&self, depth: usize) -> cached_tree_hash::BTreeSchema {
        cached_tree_hash::vec::produce_schema(&self.vec, depth)
    }

    fn update_tree_hash_cache(
        &self,
        cache: &mut cached_tree_hash::TreeHashCache,
    ) -> Result<(), cached_tree_hash::Error> {
        cached_tree_hash::vec::update_tree_hash_cache(&self.vec, cache)?;

        Ok(())
    }
}
*/

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

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.vec.ssz_append(buf)
    }
}

impl<T, N: Unsigned> ssz::Decode for VariableList<T, N>
where
    T: ssz::Decode + Default,
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
mod tests {
    use super::*;
    use ssz::*;
    use typenum::*;

    #[test]
    fn encode() {
        let vec: VariableList<u16, U2> = vec![0; 2].into();
        assert_eq!(vec.as_ssz_bytes(), vec![0, 0, 0, 0]);
        assert_eq!(<VariableList<u16, U2> as Encode>::ssz_fixed_len(), 4);
    }

    fn round_trip<T: Encode + Decode + std::fmt::Debug + PartialEq>(item: T) {
        let encoded = &item.as_ssz_bytes();
        assert_eq!(T::from_ssz_bytes(&encoded), Ok(item));
    }

    #[test]
    fn u16_len_8() {
        round_trip::<VariableList<u16, U8>>(vec![42; 8].into());
        round_trip::<VariableList<u16, U8>>(vec![0; 8].into());
    }
}
