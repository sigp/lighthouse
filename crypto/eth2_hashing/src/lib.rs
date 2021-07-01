//! Provides a simple hash function utilizing `sha2::Sha256`.
//!
//! The purpose of this crate is to provide an abstraction to whatever hash function Ethereum
//! 2.0 is using. The hash function has been subject to change during the specification process, so
//! defining it once in this crate makes it easy to replace.

pub use sha2::{Digest, Sha256};

#[cfg(feature = "zero_hash_cache")]
use lazy_static::lazy_static;

/// Returns the digest of `input`.
pub fn hash(input: &[u8]) -> Vec<u8> {
    Sha256::digest(input).into_iter().collect()
}

/// Hash function returning a fixed-size array (to save on allocations).
pub fn hash_fixed(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// Compute the hash of two slices concatenated.
///
/// # Panics
///
/// Will panic if either `h1` or `h2` are not 32 bytes in length.
pub fn hash32_concat(h1: &[u8], h2: &[u8]) -> [u8; 32] {
    let mut preimage = [0; 64];
    preimage[0..32].copy_from_slice(h1);
    preimage[32..64].copy_from_slice(h2);

    hash_fixed(&preimage)
}

/// The max index that can be used with `ZERO_HASHES`.
#[cfg(feature = "zero_hash_cache")]
pub const ZERO_HASHES_MAX_INDEX: usize = 48;

#[cfg(feature = "zero_hash_cache")]
lazy_static! {
    /// Cached zero hashes where `ZERO_HASHES[i]` is the hash of a Merkle tree with 2^i zero leaves.
    pub static ref ZERO_HASHES: Vec<Vec<u8>> = {
        let mut hashes = vec![vec![0; 32]; ZERO_HASHES_MAX_INDEX + 1];

        for i in 0..ZERO_HASHES_MAX_INDEX {
            hashes[i + 1] = hash32_concat(&hashes[i], &hashes[i])[..].to_vec();
        }

        hashes
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hex::FromHex;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_hashing() {
        let input: Vec<u8> = b"hello world".as_ref().into();

        let output = hash(input.as_ref());
        let expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let expected: Vec<u8> = expected_hex.from_hex().unwrap();
        assert_eq!(expected, output);
    }

    #[cfg(feature = "zero_hash_cache")]
    mod zero_hash {
        use super::*;

        #[test]
        fn zero_hash_zero() {
            assert_eq!(ZERO_HASHES[0], vec![0; 32]);
        }
    }
}
