//! Produces the "deterministic" validator private keys used for inter-operability testing for
//! Ethereum 2.0 clients.
//!
//! Each private key is the first hash in the sha2 hash-chain that is less than 2^255. As such,
//! keys generated here are **not secret** and are **not for production use**.
//!
//! Note: these keys have not been tested against a reference implementation, yet.
#[macro_use]
extern crate lazy_static;

use eth2_hashing::hash;
use milagro_bls::{Keypair, PublicKey, SecretKey};
use num_bigint::BigUint;

pub const CURVE_ORDER_BITS: usize = 255;
pub const PRIVATE_KEY_BYTES: usize = 48;
pub const HASH_BYTES: usize = 32;

lazy_static! {
    static ref CURVE_ORDER: BigUint =
        "52435875175126190479447740508185965837690552500527637822603658699938581184513"
            .parse::<BigUint>()
            .expect("Curve order should be valid");
}

pub fn le_private_key(validator_index: usize) -> [u8; PRIVATE_KEY_BYTES] {
    let preimage = {
        let mut bytes = [0; HASH_BYTES];
        let index = validator_index.to_le_bytes();
        bytes[0..index.len()].copy_from_slice(&index);
        bytes
    };

    let privkey = BigUint::from_bytes_le(&hash(&preimage)) % &*CURVE_ORDER;

    let mut bytes = [0; PRIVATE_KEY_BYTES];
    let privkey_bytes = privkey.to_bytes_le();
    bytes[0..privkey_bytes.len()].copy_from_slice(&privkey_bytes);
    bytes
}

pub fn keypair(validator_index: usize) -> Keypair {
    let bytes = le_private_key(validator_index);

    let sk =
        SecretKey::from_bytes(&swap_bytes(bytes.to_vec())).expect("Should be valid private key");

    Keypair {
        pk: PublicKey::from_secret_key(&sk),
        sk,
    }
}

fn swap_bytes<T>(input: Vec<T>) -> Vec<T> {
    let mut output = vec![];
    input.into_iter().rev().for_each(|byte| output.push(byte));
    output
}
