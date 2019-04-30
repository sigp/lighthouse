#[cfg(test)]
#[macro_export]
macro_rules! ssz_tests {
    ($type: ident) => {
        #[test]
        pub fn test_ssz_round_trip() {
            use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
            use ssz::{ssz_encode, Decodable};

            let mut rng = XorShiftRng::from_seed([42; 16]);
            let original = $type::random_for_test(&mut rng);

            let bytes = ssz_encode(&original);
            let (decoded, _): ($type, usize) = <_>::ssz_decode(&bytes, 0).unwrap();

            assert_eq!(original, decoded);
        }

        #[test]
        pub fn test_tree_hash_root() {
            use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
            use tree_hash::TreeHash;

            let mut rng = XorShiftRng::from_seed([42; 16]);
            let original = $type::random_for_test(&mut rng);

            let result = original.tree_hash_root();

            assert_eq!(result.len(), 32);
            // TODO: Add further tests
            // https://github.com/sigp/lighthouse/issues/170
        }
    };
}

#[cfg(test)]
#[macro_export]
macro_rules! cached_tree_hash_tests {
    ($type: ident) => {
        #[test]
        pub fn test_cached_tree_hash() {
            use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
            use tree_hash::TreeHash;

            let mut rng = XorShiftRng::from_seed([42; 16]);

            // Test the original hash
            let original = $type::random_for_test(&mut rng);
            let mut cache = cached_tree_hash::TreeHashCache::new(&original).unwrap();

            assert_eq!(
                cache.tree_hash_root().unwrap().to_vec(),
                original.tree_hash_root(),
                "Original hash failed."
            );

            // Test the updated hash
            let modified = $type::random_for_test(&mut rng);
            cache.update(&modified).unwrap();
            assert_eq!(
                cache.tree_hash_root().unwrap().to_vec(),
                modified.tree_hash_root(),
                "Modification hash failed"
            );

            // Produce a new cache for the modified object and compare it to the updated cache.
            let mut modified_cache = cached_tree_hash::TreeHashCache::new(&modified).unwrap();

            // Reset the caches.
            cache.reset_modifications();
            modified_cache.reset_modifications();

            // Ensure the modified cache is the same as a newly created cache. This is a sanity
            // check to make sure there are no artifacts of the original cache remaining after an
            // update.
            assert_eq!(
                modified_cache, cache,
                "The modified cache does not match a new cache."
            )
        }
    };
}
