//! Produces the "deterministic" validator private keys used for inter-operability testing for
//! Ethereum 2.0 clients.
//!
//! Each private key is the first hash in the sha2 hash-chain that is less than 2^255. As such,
//! keys generated here are **not secret** and are **not for production use**.
//!
//! Note: these keys have not been tested against a reference implementation, yet.

use eth2_hashing::hash;
use num_bigint::BigUint;

pub const CURVE_ORDER_BITS: usize = 255;
pub const PRIVATE_KEY_BYTES: usize = 48;
pub const HASH_BYTES: usize = 32;

fn hash_big_int_le(uint: BigUint) -> BigUint {
    let mut preimage = uint.to_bytes_le();
    preimage.resize(32, 0_u8);
    BigUint::from_bytes_le(&hash(&preimage))
}

fn private_key(validator_index: usize) -> BigUint {
    let mut key = BigUint::from(validator_index);
    loop {
        key = hash_big_int_le(key);
        if key.bits() <= CURVE_ORDER_BITS {
            break key;
        }
    }
}

/// Generates an **unsafe** BLS12-381 private key for the given validator index, where that private
/// key is represented in big-endian bytes.
pub fn be_private_key(validator_index: usize) -> [u8; PRIVATE_KEY_BYTES] {
    let vec = private_key(validator_index).to_bytes_be();

    let mut out = [0; PRIVATE_KEY_BYTES];
    out[PRIVATE_KEY_BYTES - vec.len()..PRIVATE_KEY_BYTES].copy_from_slice(&vec);
    out
}

/// Generates an **unsafe** BLS12-381 private key for the given validator index, where that private
/// key is represented in little-endian bytes.
pub fn le_private_key(validator_index: usize) -> [u8; PRIVATE_KEY_BYTES] {
    let vec = private_key(validator_index).to_bytes_le();

    let mut out = [0; PRIVATE_KEY_BYTES];
    out[0..vec.len()].copy_from_slice(&vec);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flip(vec: &[u8]) -> Vec<u8> {
        let len = vec.len();
        let mut out = vec![0; len];
        for i in 0..len {
            out[len - 1 - i] = vec[i];
        }
        out
    }

    fn pad_le_bls(mut vec: Vec<u8>) -> Vec<u8> {
        vec.resize(PRIVATE_KEY_BYTES, 0_u8);
        vec
    }

    fn pad_be_bls(mut vec: Vec<u8>) -> Vec<u8> {
        let mut out = vec![0; PRIVATE_KEY_BYTES - vec.len()];
        out.append(&mut vec);
        out
    }

    fn pad_le_hash(index: usize) -> Vec<u8> {
        let mut vec = index.to_le_bytes().to_vec();
        vec.resize(HASH_BYTES, 0_u8);
        vec
    }

    fn multihash(index: usize, rounds: usize) -> Vec<u8> {
        let mut vec = pad_le_hash(index);
        for _ in 0..rounds {
            vec = hash(&vec);
        }
        vec
    }

    fn compare(validator_index: usize, preimage: &[u8]) {
        assert_eq!(
            &le_private_key(validator_index)[..],
            &pad_le_bls(hash(preimage))[..]
        );
        assert_eq!(
            &be_private_key(validator_index)[..],
            &pad_be_bls(flip(&hash(preimage)))[..]
        );
    }

    #[test]
    fn consistency() {
        for i in 0..256 {
            let le = BigUint::from_bytes_le(&le_private_key(i));
            let be = BigUint::from_bytes_be(&be_private_key(i));
            assert_eq!(le, be);
        }
    }

    #[test]
    fn non_repeats() {
        // These indices only need one hash to be in the curve order.
        compare(0, &pad_le_hash(0));
        compare(3, &pad_le_hash(3));
    }

    #[test]
    fn repeats() {
        // Index 5 needs 5x hashes to get into the curve order.
        compare(5, &multihash(5, 5));
    }

    #[test]
    fn doesnt_panic() {
        for i in 0..256 {
            be_private_key(i);
            le_private_key(i);
        }
    }
}
