//! SSZ bytes do not say which format a list hashes in, so `Decode` builds the
//! fixed format and a progressive field decodes through `progressive`.

mod serde_codec;
mod ssz_codec;

pub mod progressive;
pub mod quoted_u64;

use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use milhouse::Error;
use silver_hashing::{B256, HashFormat, ListError, SharedList, SszScalar, TreeSpec};
use tree_hash::{Hash256, PackedEncoding, TreeHash, TreeHashType};
use typenum::Unsigned;

pub struct Spec<T, N>(PhantomData<(T, N)>);

impl<T: SszScalar, N: Unsigned> TreeSpec for Spec<T, N> {
    type Val = T;
    type Page = [B256; 128];
    const SSZ_LIMIT: usize = N::USIZE;
}

/// Newtype so the `tree_hash`/`ssz`/serde impls can live here, next to the
/// state that needs them.
pub struct ScalarList<T: SszScalar, N: Unsigned>(SharedList<Spec<T, N>>);

impl<T: SszScalar, N: Unsigned> ScalarList<T, N> {
    pub fn new(values: Vec<T>, format: HashFormat) -> Result<Self, Error> {
        SharedList::new(&values, format)
            .map(Self)
            .map_err(milhouse_error)
    }

    pub fn try_from_iter(
        iter: impl IntoIterator<Item = T>,
        format: HashFormat,
    ) -> Result<Self, Error> {
        Self::new(iter.into_iter().collect(), format)
    }

    pub fn repeat(elem: T, n: usize, format: HashFormat) -> Result<Self, Error> {
        Self::new(vec![elem; n], format)
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.iter().collect()
    }

    #[inline]
    pub fn set(&mut self, i: usize, v: T) -> Result<(), Error> {
        self.0.set(i, v).map_err(milhouse_error)
    }

    pub fn push(&mut self, v: T) -> Result<(), Error> {
        self.0.push(v).map_err(milhouse_error)
    }
}

impl<T: SszScalar, N: Unsigned> Deref for ScalarList<T, N> {
    type Target = SharedList<Spec<T, N>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: SszScalar, N: Unsigned> DerefMut for ScalarList<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

fn milhouse_error(e: ListError) -> Error {
    match e {
        ListError::OutOfBounds { index, len } => Error::OutOfBoundsUpdate { index, len },
        ListError::Full { limit } => Error::ListFull { len: limit },
    }
}

impl<T: SszScalar, N: Unsigned> Clone for ScalarList<T, N> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: SszScalar, N: Unsigned> Default for ScalarList<T, N> {
    fn default() -> Self {
        Self::new(Vec::new(), HashFormat::Fixed).expect("empty list fits any limit")
    }
}

impl<T: SszScalar, N: Unsigned> PartialEq for ScalarList<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl<T: SszScalar, N: Unsigned> std::fmt::Debug for ScalarList<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScalarList")
            .field("len", &self.len())
            .field("committed", &self.is_committed())
            .finish()
    }
}

impl<T: SszScalar, N: Unsigned> TreeHash for ScalarList<T, N> {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        unreachable!("ScalarList should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("ScalarList should never be packed.")
    }

    fn tree_hash_root(&self) -> Hash256 {
        Hash256::from(self.0.hash_root())
    }
}

impl<T: SszScalar, N: Unsigned> ssz::TryFromIter<T> for ScalarList<T, N> {
    type Error = Error;

    fn try_from_iter<I: IntoIterator<Item = T>>(iter: I) -> Result<Self, Error> {
        Self::new(iter.into_iter().collect(), HashFormat::Fixed)
    }
}
