macro_rules! impl_ssz {
    ($type: ident, $byte_size: expr, $item_str: expr) => {
        impl ssz::Encode for $type {
            fn is_ssz_fixed_len() -> bool {
                true
            }

            fn ssz_fixed_len() -> usize {
                $byte_size
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                buf.append(&mut self.as_bytes())
            }
        }

        impl ssz::Decode for $type {
            fn is_ssz_fixed_len() -> bool {
                true
            }

            fn ssz_fixed_len() -> usize {
                $byte_size
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
                let len = bytes.len();
                let expected = <Self as ssz::Decode>::ssz_fixed_len();

                if len != expected {
                    Err(ssz::DecodeError::InvalidByteLength { len, expected })
                } else {
                    $type::from_bytes(bytes)
                }
            }
        }
    };
}

macro_rules! impl_tree_hash {
    ($type: ty, $byte_size: ident) => {
        impl tree_hash::TreeHash for $type {
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
                let vector: ssz_types::FixedVector<u8, ssz_types::typenum::$byte_size> =
                    ssz_types::FixedVector::from(self.as_ssz_bytes());
                vector.tree_hash_root()
            }
        }
    };
}

macro_rules! impl_cached_tree_hash {
    ($type: ty, $byte_size: ident) => {
        impl cached_tree_hash::CachedTreeHash for $type {
            fn new_tree_hash_cache(
                &self,
                _depth: usize,
            ) -> Result<cached_tree_hash::TreeHashCache, cached_tree_hash::Error> {
                unimplemented!("CachedTreeHash is not implemented for BLS types")
            }

            fn tree_hash_cache_schema(&self, _depth: usize) -> cached_tree_hash::BTreeSchema {
                unimplemented!("CachedTreeHash is not implemented for BLS types")
            }

            fn update_tree_hash_cache(
                &self,
                _cache: &mut cached_tree_hash::TreeHashCache,
            ) -> Result<(), cached_tree_hash::Error> {
                unimplemented!("CachedTreeHash is not implemented for BLS types")
            }
        }
    };
}
