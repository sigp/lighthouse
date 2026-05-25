#![allow(clippy::arithmetic_side_effects)]

#[macro_use]
mod macros;
mod generate_deterministic_keypairs;
#[cfg(test)]
mod generate_random_block_and_blobs;

pub use generate_deterministic_keypairs::generate_deterministic_keypair;
pub use generate_deterministic_keypairs::generate_deterministic_keypairs;
pub use generate_deterministic_keypairs::load_keypairs_from_yaml;

/// Deterministic 256 KiB seed.
#[cfg(feature = "arbitrary")]
static SEED: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
    use rand::RngCore;
    use rand::SeedableRng;
    let mut bytes = vec![0u8; 256 * 1024];
    rand_xorshift::XorShiftRng::from_seed([0x42; 16]).fill_bytes(&mut bytes);
    bytes
});

/// Generates an arbitrary instance of `T` from a deterministic seed.
/// Suitable for one-shot test instance creation.
#[cfg(feature = "arbitrary")]
pub fn test_arbitrary_instance<'a, T: arbitrary::Arbitrary<'a>>() -> T {
    let mut u = arbitrary::Unstructured::new(&SEED);
    T::arbitrary(&mut u).expect("sufficient bytes for arbitrary generation")
}

/// Returns an `Unstructured` from a deterministic seed.
/// Use this when you need to pass an `Unstructured` to helpers like
/// `generate_rand_block_and_blobs`.
#[cfg(feature = "arbitrary")]
pub fn test_unstructured() -> arbitrary::Unstructured<'static> {
    arbitrary::Unstructured::new(&SEED)
}

use ssz::{Decode, Encode, ssz_encode};
use std::fmt::Debug;
use tree_hash::TreeHash;

pub fn test_ssz_tree_hash_pair<T, U>(v1: &T, v2: &U)
where
    T: TreeHash + Encode + Decode + Debug + PartialEq,
    U: TreeHash + Encode + Decode + Debug + PartialEq,
{
    test_ssz_tree_hash_pair_with(v1, v2, T::from_ssz_bytes)
}

pub fn test_ssz_tree_hash_pair_with<T, U>(
    v1: &T,
    v2: &U,
    t_decoder: impl FnOnce(&[u8]) -> Result<T, ssz::DecodeError>,
) where
    T: TreeHash + Encode + Debug + PartialEq,
    U: TreeHash + Encode + Decode + Debug + PartialEq,
{
    // SSZ encoding should agree between the two types.
    let encoding1 = ssz_encode(v1);
    let encoding2 = ssz_encode(v2);
    assert_eq!(encoding1, encoding2);

    // Decoding the encoding should yield either value.
    let decoded1 = t_decoder(&encoding1).unwrap();
    assert_eq!(&decoded1, v1);

    let decoded2 = U::from_ssz_bytes(&encoding1).unwrap();
    assert_eq!(&decoded2, v2);

    // Tree hashing should agree.
    assert_eq!(v1.tree_hash_root(), v2.tree_hash_root());
}
