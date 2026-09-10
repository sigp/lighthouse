//! Read-only view over a list that is a [`VariableList`] in some forks and a
//! [`ProgressiveVariableList`] from Gloas onwards (EIP-7688).

use ssz_types::typenum::Unsigned;
use ssz_types::{ProgressiveVariableList, VariableList};

/// View over a list that is a `VariableList` pre-Gloas and a `ProgressiveVariableList` from Gloas
/// onwards (EIP-7688). Both variants back onto a flat slice.
#[derive(Debug)]
pub enum ListRef<'a, T, N: Unsigned> {
    Basic(&'a VariableList<T, N>),
    Progressive(&'a ProgressiveVariableList<T>),
}

// Manual `Clone`/`Copy` impls to avoid spurious `T: Clone`/`T: Copy` bounds from the derive.
impl<T, N: Unsigned> Clone for ListRef<'_, T, N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T, N: Unsigned> Copy for ListRef<'_, T, N> {}

impl<'a, T, N: Unsigned> ListRef<'a, T, N> {
    /// The underlying contents as a slice.
    pub fn as_slice(self) -> &'a [T] {
        match self {
            Self::Basic(list) => list,
            Self::Progressive(list) => list,
        }
    }

    pub fn len(self) -> usize {
        self.as_slice().len()
    }

    pub fn is_empty(self) -> bool {
        self.as_slice().is_empty()
    }

    pub fn get(self, index: usize) -> Option<&'a T> {
        self.as_slice().get(index)
    }

    pub fn first(self) -> Option<&'a T> {
        self.as_slice().first()
    }

    pub fn iter(self) -> std::slice::Iter<'a, T> {
        self.as_slice().iter()
    }

    pub fn to_vec(self) -> Vec<T>
    where
        T: Clone,
    {
        self.as_slice().to_vec()
    }

    /// Borrow the contents as a slice, for passing lists to functions taking `Cow<[T]>`.
    pub fn to_cow_slice(self) -> std::borrow::Cow<'a, [T]>
    where
        T: Clone,
    {
        std::borrow::Cow::Borrowed(self.as_slice())
    }
}

impl<'a, T, N: Unsigned> IntoIterator for ListRef<'a, T, N> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T, N: Unsigned> IntoIterator for &ListRef<'a, T, N> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
