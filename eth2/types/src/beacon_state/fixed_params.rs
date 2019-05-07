use std::borrow::{Borrow, BorrowMut};
use std::marker::PhantomData;
use std::ops::{Deref, Index, IndexMut};
use std::slice::SliceIndex;
use typenum::Unsigned;

pub struct FixedLenVec<T, N>
where
    N: Unsigned,
{
    vec: Vec<T>,
    _phantom: PhantomData<N>,
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

impl<T, N: Unsigned> FixedLenVec<T, N> {
    pub fn capacity() -> usize {
        N::to_usize()
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

#[cfg(test)]
mod test {
    use super::*;
    use typenum::U8192;

    #[test]
    fn slice_ops() {
        let vec = vec![1, 2];

        let mut fixed: FixedLenVec<u64, U8192> = vec.clone().into();

        assert_eq!(fixed[0], 1);
        assert_eq!(&fixed[0..1], &vec[0..1]);
        assert_eq!(&fixed[..], &vec[..]);

        fixed[1] = 3;
        assert_eq!(fixed[1], 3);
    }
}

/*
pub trait FixedParams {
    type LatestCrosslinks:
}
*/
