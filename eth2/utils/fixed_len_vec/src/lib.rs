use serde_derive::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::ops::{Deref, Index, IndexMut};
use std::slice::SliceIndex;
use typenum::Unsigned;

pub use typenum;

mod impls;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FixedLenVec<T, N> {
    vec: Vec<T>,
    _phantom: PhantomData<N>,
}

impl<T, N: Unsigned> FixedLenVec<T, N> {
    pub fn len(&self) -> usize {
        self.vec.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity() -> usize {
        N::to_usize()
    }
}

impl<T: Default, N: Unsigned> From<Vec<T>> for FixedLenVec<T, N> {
    fn from(mut vec: Vec<T>) -> Self {
        vec.resize_with(Self::capacity(), Default::default);

        Self {
            vec,
            _phantom: PhantomData,
        }
    }
}

impl<T, N: Unsigned> Into<Vec<T>> for FixedLenVec<T, N> {
    fn into(self) -> Vec<T> {
        self.vec
    }
}

impl<T, N: Unsigned> Default for FixedLenVec<T, N> {
    fn default() -> Self {
        Self {
            vec: Vec::default(),
            _phantom: PhantomData,
        }
    }
}

impl<T, N: Unsigned, I: SliceIndex<[T]>> Index<I> for FixedLenVec<T, N> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&self.vec, index)
    }
}

impl<T, N: Unsigned, I: SliceIndex<[T]>> IndexMut<I> for FixedLenVec<T, N> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut self.vec, index)
    }
}

impl<T, N: Unsigned> Deref for FixedLenVec<T, N> {
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
    fn indexing() {
        let vec = vec![1, 2];

        let mut fixed: FixedLenVec<u64, U8192> = vec.clone().into();

        assert_eq!(fixed[0], 1);
        assert_eq!(&fixed[0..1], &vec[0..1]);
        assert_eq!((&fixed[..]).len(), 8192);

        fixed[1] = 3;
        assert_eq!(fixed[1], 3);
    }

    #[test]
    fn length() {
        let vec = vec![42; 5];
        let fixed: FixedLenVec<u64, U4> = FixedLenVec::from(vec.clone());
        assert_eq!(&fixed[..], &vec[0..4]);

        let vec = vec![42; 3];
        let fixed: FixedLenVec<u64, U4> = FixedLenVec::from(vec.clone());
        assert_eq!(&fixed[0..3], &vec[..]);
        assert_eq!(&fixed[..], &vec![42, 42, 42, 0][..]);

        let vec = vec![];
        let fixed: FixedLenVec<u64, U4> = FixedLenVec::from(vec.clone());
        assert_eq!(&fixed[..], &vec![0, 0, 0, 0][..]);
    }

    #[test]
    fn deref() {
        let vec = vec![0, 2, 4, 6];
        let fixed: FixedLenVec<u64, U4> = FixedLenVec::from(vec);

        assert_eq!(fixed.get(0), Some(&0));
        assert_eq!(fixed.get(3), Some(&6));
        assert_eq!(fixed.get(4), None);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
