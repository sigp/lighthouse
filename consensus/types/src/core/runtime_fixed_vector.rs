//! Emulates a fixed size array but with the length set at runtime.
//!
//! The length of the list cannot be changed once it is set.

#[derive(Clone, Debug)]
pub struct RuntimeFixedVector<T> {
    vec: Vec<T>,
    len: usize,
}

impl<T: Clone + Default> RuntimeFixedVector<T> {
    pub fn new(vec: Vec<T>) -> Self {
        let len = vec.len();
        Self { vec, len }
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.vec.clone()
    }

    pub fn as_slice(&self) -> &[T] {
        self.vec.as_slice()
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn into_vec(self) -> Vec<T> {
        self.vec
    }

    pub fn default(max_len: usize) -> Self {
        Self {
            vec: vec![T::default(); max_len],
            len: max_len,
        }
    }

    pub fn take(&mut self) -> Self {
        let new = std::mem::take(&mut self.vec);
        *self = Self::new(vec![T::default(); self.len]);
        Self {
            vec: new,
            len: self.len,
        }
    }
}

impl<T> std::ops::Deref for RuntimeFixedVector<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.vec[..]
    }
}

impl<T> std::ops::DerefMut for RuntimeFixedVector<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.vec[..]
    }
}

impl<T> IntoIterator for RuntimeFixedVector<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.vec.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a RuntimeFixedVector<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.vec.iter()
    }
}
