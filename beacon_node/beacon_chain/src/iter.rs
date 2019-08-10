use store::iter::{BlockRootsIterator, StateRootsIterator};
use types::{Hash256, Slot};

pub type ReverseBlockRootIterator<'a, E, S> =
    ReverseHashAndSlotIterator<BlockRootsIterator<'a, E, S>>;
pub type ReverseStateRootIterator<'a, E, S> =
    ReverseHashAndSlotIterator<StateRootsIterator<'a, E, S>>;

pub type ReverseHashAndSlotIterator<I> = ReverseChainIterator<(Hash256, Slot), I>;

/// Provides a wrapper for an iterator that returns a given `T` before it starts returning results of
/// the `Iterator`.
pub struct ReverseChainIterator<T, I> {
    first_value_used: bool,
    first_value: T,
    iter: I,
}

impl<T, I> ReverseChainIterator<T, I>
where
    T: Sized,
    I: Iterator<Item = T> + Sized,
{
    pub fn new(first_value: T, iter: I) -> Self {
        Self {
            first_value_used: false,
            first_value,
            iter,
        }
    }
}

impl<T, I> Iterator for ReverseChainIterator<T, I>
where
    T: Clone,
    I: Iterator<Item = T>,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first_value_used {
            self.iter.next()
        } else {
            self.first_value_used = true;
            Some(self.first_value.clone())
        }
    }
}
