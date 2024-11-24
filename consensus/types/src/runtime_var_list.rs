use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz::Decode;
use ssz_types::Error;
use std::ops::{Deref, DerefMut, Index, IndexMut};
use std::slice::SliceIndex;

/// Emulates a SSZ `List`.
///
/// An ordered, heap-allocated, variable-length, homogeneous collection of `T`, with no more than
/// `max_len` values.
///
/// ## Example
///
/// ```
/// use types::{RuntimeVariableList};
///
/// let base: Vec<u64> = vec![1, 2, 3, 4];
///
/// // Create a `RuntimeVariableList` from a `Vec` that has the expected length.
/// let exact: RuntimeVariableList<_> = RuntimeVariableList::from_vec(base.clone(), 4);
/// assert_eq!(&exact[..], &[1, 2, 3, 4]);
///
/// // Create a `RuntimeVariableList` from a `Vec` that is too long and the `Vec` is truncated.
/// let short: RuntimeVariableList<_> = RuntimeVariableList::from_vec(base.clone(), 3);
/// assert_eq!(&short[..], &[1, 2, 3]);
///
/// // Create a `RuntimeVariableList` from a `Vec` that is shorter than the maximum.
/// let mut long: RuntimeVariableList<_> = RuntimeVariableList::from_vec(base, 5);
/// assert_eq!(&long[..], &[1, 2, 3, 4]);
///
/// // Push a value to if it does not exceed the maximum
/// long.push(5).unwrap();
/// assert_eq!(&long[..], &[1, 2, 3, 4, 5]);
///
/// // Push a value to if it _does_ exceed the maximum.
/// assert!(long.push(6).is_err());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Derivative)]
#[derivative(PartialEq, Eq, Hash(bound = "T: std::hash::Hash"))]
#[serde(transparent)]
pub struct RuntimeVariableList<T> {
    vec: Vec<T>,
    #[serde(skip)]
    max_len: usize,
}

impl<T> RuntimeVariableList<T> {
    /// Returns `Ok` if the given `vec` equals the fixed length of `Self`. Otherwise returns
    /// `Err(OutOfBounds { .. })`.
    pub fn new(vec: Vec<T>, max_len: usize) -> Result<Self, Error> {
        if vec.len() <= max_len {
            Ok(Self { vec, max_len })
        } else {
            Err(Error::OutOfBounds {
                i: vec.len(),
                len: max_len,
            })
        }
    }

    pub fn from_vec(mut vec: Vec<T>, max_len: usize) -> Self {
        vec.truncate(max_len);

        Self { vec, max_len }
    }

    /// Create an empty list.
    pub fn empty(max_len: usize) -> Self {
        Self {
            vec: vec![],
            max_len,
        }
    }

    pub fn as_slice(&self) -> &[T] {
        self.vec.as_slice()
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
    pub fn max_len(&self) -> usize {
        self.max_len
    }

    /// Appends `value` to the back of `self`.
    ///
    /// Returns `Err(())` when appending `value` would exceed the maximum length.
    pub fn push(&mut self, value: T) -> Result<(), Error> {
        if self.vec.len() < self.max_len {
            self.vec.push(value);
            Ok(())
        } else {
            Err(Error::OutOfBounds {
                i: self.vec.len().saturating_add(1),
                len: self.max_len,
            })
        }
    }
}

impl<T: Decode> RuntimeVariableList<T> {
    pub fn from_ssz_bytes(bytes: &[u8], max_len: usize) -> Result<Self, ssz::DecodeError> {
        let vec = if bytes.is_empty() {
            vec![]
        } else if <T as Decode>::is_ssz_fixed_len() {
            let num_items = bytes
                .len()
                .checked_div(<T as Decode>::ssz_fixed_len())
                .ok_or(ssz::DecodeError::ZeroLengthItem)?;

            if num_items > max_len {
                return Err(ssz::DecodeError::BytesInvalid(format!(
                    "RuntimeVariableList of {} items exceeds maximum of {}",
                    num_items, max_len
                )));
            }

            bytes
                .chunks(<T as Decode>::ssz_fixed_len())
                .try_fold(Vec::with_capacity(num_items), |mut vec, chunk| {
                    vec.push(<T as Decode>::from_ssz_bytes(chunk)?);
                    Ok(vec)
                })
                .map(Into::into)?
        } else {
            ssz::decode_list_of_variable_length_items(bytes, Some(max_len))?
        };
        Ok(Self { vec, max_len })
    }
}

impl<T> From<RuntimeVariableList<T>> for Vec<T> {
    fn from(list: RuntimeVariableList<T>) -> Vec<T> {
        list.vec
    }
}

impl<T, I: SliceIndex<[T]>> Index<I> for RuntimeVariableList<T> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&self.vec, index)
    }
}

impl<T, I: SliceIndex<[T]>> IndexMut<I> for RuntimeVariableList<T> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut self.vec, index)
    }
}

impl<T> Deref for RuntimeVariableList<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.vec[..]
    }
}

impl<T> DerefMut for RuntimeVariableList<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.vec[..]
    }
}

impl<'a, T> IntoIterator for &'a RuntimeVariableList<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T> IntoIterator for RuntimeVariableList<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.vec.into_iter()
    }
}

impl<T> ssz::Encode for RuntimeVariableList<T>
where
    T: ssz::Encode,
{
    fn is_ssz_fixed_len() -> bool {
        <Vec<T>>::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.vec.ssz_append(buf)
    }

    fn ssz_fixed_len() -> usize {
        <Vec<T>>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.vec.ssz_bytes_len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ssz::*;
    use std::fmt::Debug;

    #[test]
    fn new() {
        let vec = vec![42; 5];
        let fixed: Result<RuntimeVariableList<u64>, _> = RuntimeVariableList::new(vec, 4);
        assert!(fixed.is_err());

        let vec = vec![42; 3];
        let fixed: Result<RuntimeVariableList<u64>, _> = RuntimeVariableList::new(vec, 4);
        assert!(fixed.is_ok());

        let vec = vec![42; 4];
        let fixed: Result<RuntimeVariableList<u64>, _> = RuntimeVariableList::new(vec, 4);
        assert!(fixed.is_ok());
    }

    #[test]
    fn indexing() {
        let vec = vec![1, 2];

        let mut fixed: RuntimeVariableList<u64> = RuntimeVariableList::from_vec(vec.clone(), 8192);

        assert_eq!(fixed[0], 1);
        assert_eq!(&fixed[0..1], &vec[0..1]);
        assert_eq!(fixed[..].len(), 2);

        fixed[1] = 3;
        assert_eq!(fixed[1], 3);
    }

    #[test]
    fn length() {
        let vec = vec![42; 5];
        let fixed: RuntimeVariableList<u64> = RuntimeVariableList::from_vec(vec.clone(), 4);
        assert_eq!(&fixed[..], &vec[0..4]);

        let vec = vec![42; 3];
        let fixed: RuntimeVariableList<u64> = RuntimeVariableList::from_vec(vec.clone(), 4);
        assert_eq!(&fixed[0..3], &vec[..]);
        assert_eq!(&fixed[..], &vec![42, 42, 42][..]);

        let vec = vec![];
        let fixed: RuntimeVariableList<u64> = RuntimeVariableList::from_vec(vec, 4);
        assert_eq!(&fixed[..], &[] as &[u64]);
    }

    #[test]
    fn deref() {
        let vec = vec![0, 2, 4, 6];
        let fixed: RuntimeVariableList<u64> = RuntimeVariableList::from_vec(vec, 4);

        assert_eq!(fixed.first(), Some(&0));
        assert_eq!(fixed.get(3), Some(&6));
        assert_eq!(fixed.get(4), None);
    }

    #[test]
    fn encode() {
        let vec: RuntimeVariableList<u16> = RuntimeVariableList::from_vec(vec![0; 2], 2);
        assert_eq!(vec.as_ssz_bytes(), vec![0, 0, 0, 0]);
        assert_eq!(<RuntimeVariableList<u16> as Encode>::ssz_fixed_len(), 4);
    }

    fn round_trip<T: Encode + Decode + PartialEq + Debug>(item: RuntimeVariableList<T>) {
        let max_len = item.max_len();
        let encoded = &item.as_ssz_bytes();
        assert_eq!(item.ssz_bytes_len(), encoded.len());
        assert_eq!(
            RuntimeVariableList::from_ssz_bytes(encoded, max_len),
            Ok(item)
        );
    }

    #[test]
    fn u16_len_8() {
        round_trip::<u16>(RuntimeVariableList::from_vec(vec![42; 8], 8));
        round_trip::<u16>(RuntimeVariableList::from_vec(vec![0; 8], 8));
    }
}
