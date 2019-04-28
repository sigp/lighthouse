use crate::test_utils::{RngCore, TestRandom};
use cached_tree_hash::CachedTreeHash;
use serde_derive::{Deserialize, Serialize};
use ssz::{Decodable, DecodeError, Encodable, SszStream};
use std::ops::{Deref, DerefMut};
use tree_hash::TreeHash;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct TreeHashVector<T>(Vec<T>);

impl<T> From<Vec<T>> for TreeHashVector<T> {
    fn from(vec: Vec<T>) -> TreeHashVector<T> {
        TreeHashVector(vec)
    }
}

impl<T> Into<Vec<T>> for TreeHashVector<T> {
    fn into(self) -> Vec<T> {
        self.0
    }
}

impl<T> Deref for TreeHashVector<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Vec<T> {
        &self.0
    }
}

impl<T> DerefMut for TreeHashVector<T> {
    fn deref_mut(&mut self) -> &mut Vec<T> {
        &mut self.0
    }
}

impl<T> tree_hash::TreeHash for TreeHashVector<T>
where
    T: TreeHash,
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
        tree_hash::impls::vec_tree_hash_root(self)
    }
}

impl<T> CachedTreeHash for TreeHashVector<T>
where
    T: CachedTreeHash + TreeHash,
{
    fn new_tree_hash_cache(
        &self,
        depth: usize,
    ) -> Result<cached_tree_hash::TreeHashCache, cached_tree_hash::Error> {
        let (cache, _overlay) = cached_tree_hash::impls::vec::new_tree_hash_cache(self, depth)?;

        Ok(cache)
    }

    fn tree_hash_cache_schema(&self, depth: usize) -> cached_tree_hash::BTreeSchema {
        cached_tree_hash::impls::vec::produce_schema(self, depth)
    }

    fn update_tree_hash_cache(
        &self,
        cache: &mut cached_tree_hash::TreeHashCache,
    ) -> Result<(), cached_tree_hash::Error> {
        cached_tree_hash::impls::vec::update_tree_hash_cache(self, cache)?;

        Ok(())
    }
}

impl<T> Encodable for TreeHashVector<T>
where
    T: Encodable,
{
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(self)
    }
}

impl<T> Decodable for TreeHashVector<T>
where
    T: Decodable,
{
    fn ssz_decode(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
        ssz::decode_ssz_list(bytes, index).and_then(|(vec, i)| Ok((vec.into(), i)))
    }
}

impl<T: RngCore, U> TestRandom<T> for TreeHashVector<U>
where
    U: TestRandom<T>,
{
    fn random_for_test(rng: &mut T) -> Self {
        TreeHashVector::from(vec![
            U::random_for_test(rng),
            U::random_for_test(rng),
            U::random_for_test(rng),
        ])
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tree_hash::TreeHash;

    #[test]
    pub fn test_cached_tree_hash() {
        let original = TreeHashVector::from(vec![1_u64, 2, 3, 4]);

        let mut hasher = cached_tree_hash::CachedTreeHasher::new(&original).unwrap();

        assert_eq!(hasher.tree_hash_root().unwrap(), original.tree_hash_root());

        let modified = TreeHashVector::from(vec![1_u64, 1, 1, 1]);

        hasher.update(&modified).unwrap();

        assert_eq!(hasher.tree_hash_root().unwrap(), modified.tree_hash_root());
    }

}
