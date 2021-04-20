#![allow(clippy::integer_arithmetic)]

use std::fmt::Debug;

pub use rand::{RngCore, SeedableRng};
pub use rand_xorshift::XorShiftRng;

pub use generate_deterministic_keypairs::generate_deterministic_keypair;
pub use generate_deterministic_keypairs::generate_deterministic_keypairs;
pub use generate_deterministic_keypairs::load_keypairs_from_yaml;
use ssz::{ssz_encode, Decode, Encode};
pub use test_random::{test_random_instance, TestRandom};
use tree_hash::TreeHash;

#[macro_use]
mod macros;
mod generate_deterministic_keypairs;
mod test_random;

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
