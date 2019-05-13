use super::*;
// use cached_tree_hash::CachedTreeHash;
// use ssz::{Decode, Encode};
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

impl<T, N: Unsigned> ssz::Encode for FixedLenVec<T, N>
where
    T: ssz::Encode,
{
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        if <Self as ssz::Encode>::is_ssz_fixed_len() {
            T::ssz_fixed_len() * N::to_usize()
        } else {
            ssz::BYTES_PER_LENGTH_OFFSET
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        if T::is_ssz_fixed_len() {
            buf.reserve(T::ssz_fixed_len() * self.len());

            for item in &self.vec {
                item.ssz_append(buf);
            }
        } else {
            let mut encoder = ssz::SszEncoder::list(buf, self.len() * ssz::BYTES_PER_LENGTH_OFFSET);

            for item in &self.vec {
                encoder.append(item);
            }

            encoder.finalize();
        }
    }
}

impl<T, N: Unsigned> ssz::Decode for FixedLenVec<T, N>
where
    T: ssz::Decode + Default,
{
    fn is_ssz_fixed_len() -> bool {
        T::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        if <Self as ssz::Decode>::is_ssz_fixed_len() {
            T::ssz_fixed_len() * N::to_usize()
        } else {
            ssz::BYTES_PER_LENGTH_OFFSET
        }
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        if bytes.len() == 0 {
            Ok(FixedLenVec::from(vec![]))
        } else if T::is_ssz_fixed_len() {
            bytes
                .chunks(T::ssz_fixed_len())
                .map(|chunk| T::from_ssz_bytes(chunk))
                .collect::<Result<Vec<T>, _>>()
                .and_then(|vec| Ok(vec.into()))
        } else {
            ssz::decode_list_of_variable_length_items(bytes).and_then(|vec| Ok(vec.into()))
        }
    }
}

#[cfg(test)]
mod ssz_tests {
    use super::*;
    use ssz::*;
    use typenum::*;

    #[test]
    fn encode() {
        let vec: FixedLenVec<u16, U2> = vec![0; 2].into();
        assert_eq!(vec.as_ssz_bytes(), vec![0, 0, 0, 0]);
        assert_eq!(<FixedLenVec<u16, U2> as Encode>::ssz_fixed_len(), 4);
    }

    fn round_trip<T: Encode + Decode + std::fmt::Debug + PartialEq>(item: T) {
        let encoded = &item.as_ssz_bytes();
        assert_eq!(T::from_ssz_bytes(&encoded), Ok(item));
    }

    #[test]
    fn u16_len_8() {
        round_trip::<FixedLenVec<u16, U8>>(vec![42; 8].into());
        round_trip::<FixedLenVec<u16, U8>>(vec![0; 8].into());
    }
}
