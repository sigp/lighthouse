//! Provides a simple hash function utilizing `ring::digest::SHA256`.
//!
//! The purpose of this crate is to provide an abstraction to whatever hash function Ethereum
//! 2.0 is using. The hash function has been subject to change during the specification process, so
//! defining it once in this crate makes it easy to replace.

#[cfg(not(target_arch = "wasm32"))]
use ring::digest::{digest, SHA256};

#[cfg(target_arch = "wasm32")]
use sha2::{Digest, Sha256};

/// Returns the digest of `input`.
///
/// Uses `ring::digest::SHA256`.
pub fn hash(input: &[u8]) -> Vec<u8> {
    #[cfg(not(target_arch = "wasm32"))]
    let h = digest(&SHA256, input).as_ref().into();

    #[cfg(target_arch = "wasm32")]
    let h = Sha256::digest(input).as_ref().into();

    h
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
}
