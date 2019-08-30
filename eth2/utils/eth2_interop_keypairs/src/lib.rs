//! Produces the "deterministic" validator private keys used for inter-operability testing for
//! Ethereum 2.0 clients.
//!
//! Each private key is the sha2 hash of the validator index (little-endian, padded to 32 bytes),
//! modulo the BLS-381 curve order.
//!
//! Keys generated here are **not secret** and are **not for production use**. It is trivial to
//! know the secret key for any validator.
//!
//!## Reference
//!
//! Reference implementation:
//!
//! https://github.com/ethereum/eth2.0-pm/blob/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start/keygen.py
//!
//!
//! This implementation passes the [reference implementation
//! tests](https://github.com/ethereum/eth2.0-pm/blob/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start/keygen_test_vector.yaml).
#[macro_use]
extern crate lazy_static;

use eth2_hashing::hash;
use milagro_bls::{Keypair, PublicKey, SecretKey};
use num_bigint::BigUint;

pub const PRIVATE_KEY_BYTES: usize = 48;
pub const HASH_BYTES: usize = 32;

lazy_static! {
    static ref CURVE_ORDER: BigUint =
        "52435875175126190479447740508185965837690552500527637822603658699938581184513"
            .parse::<BigUint>()
            .expect("Curve order should be valid");
}

/// Return a G1 point for the given `validator_index`, encoded as a compressed point in
/// big-endian byte-ordering.
pub fn be_private_key(validator_index: usize) -> [u8; PRIVATE_KEY_BYTES] {
    let preimage = {
        let mut bytes = [0; HASH_BYTES];
        let index = validator_index.to_le_bytes();
        bytes[0..index.len()].copy_from_slice(&index);
        bytes
    };

    let privkey = BigUint::from_bytes_le(&hash(&preimage)) % &*CURVE_ORDER;

    let mut bytes = [0; PRIVATE_KEY_BYTES];
    let privkey_bytes = privkey.to_bytes_be();
    bytes[PRIVATE_KEY_BYTES - privkey_bytes.len()..].copy_from_slice(&privkey_bytes);
    bytes
}

/// Return a public and private keypair for a given `validator_index`.
pub fn keypair(validator_index: usize) -> Keypair {
    let sk = SecretKey::from_bytes(&be_private_key(validator_index)).expect(&format!(
        "Should build valid private key for validator index {}",
        validator_index
    ));

    Keypair {
        pk: PublicKey::from_secret_key(&sk),
        sk,
    }
}
