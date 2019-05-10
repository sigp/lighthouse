use super::*;
// use cached_tree_hash::CachedTreeHash;
// use ssz::{Decodable, Encodable};
// use tree_hash::TreeHash;

impl<T, N: Unsigned> tree_hash::TreeHash for FixedLenVec<T, N>
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

impl<T, N: Unsigned> cached_tree_hash::CachedTreeHash for FixedLenVec<T, N>
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

impl<T, N: Unsigned> ssz::Encodable for FixedLenVec<T, N>
where
    T: ssz::Encodable,
{
    fn ssz_append(&self, s: &mut ssz::SszStream) {
        s.append_vec(&self.vec)
    }
}

impl<T, N: Unsigned> ssz::Decodable for FixedLenVec<T, N>
where
    T: ssz::Decodable + Default,
{
    fn ssz_decode(bytes: &[u8], index: usize) -> Result<(Self, usize), ssz::DecodeError> {
        ssz::decode_ssz_list(bytes, index).and_then(|(vec, i)| Ok((vec.into(), i)))
    }
}
