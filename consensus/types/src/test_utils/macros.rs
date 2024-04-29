#![cfg(test)]

#[macro_export]
macro_rules! ssz_and_tree_hash_tests {
    ($type: ty) => {
        ssz_tests!($type);
        tree_hash_tests!($type);
    };
}

#[macro_export]
macro_rules! ssz_tests {
    ($type: ty) => {
        #[test]
        pub fn test_ssz_round_trip() {
            use ssz::{ssz_encode, Decode};
            use $crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};

            let mut rng = XorShiftRng::from_seed([42; 16]);
            let original = <$type>::random_for_test(&mut rng);

            let bytes = ssz_encode(&original);
            let decoded = <$type>::from_ssz_bytes(&bytes).unwrap();

            assert_eq!(original, decoded);
        }
    };
}

#[macro_export]
macro_rules! tree_hash_tests {
    ($type: ty) => {
        #[test]
        pub fn test_tree_hash_root() {
            use tree_hash::TreeHash;
            use $crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};

            let mut rng = XorShiftRng::from_seed([42; 16]);
            let original = <$type>::random_for_test(&mut rng);

            // Tree hashing should not panic.
            original.tree_hash_root();
        }
    };
}
