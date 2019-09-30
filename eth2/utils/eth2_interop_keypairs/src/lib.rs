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
use serde_derive::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fs::File;
use std::path::PathBuf;

pub const PRIVATE_KEY_BYTES: usize = 48;
pub const PUBLIC_KEY_BYTES: usize = 48;
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
    let sk = SecretKey::from_bytes(&be_private_key(validator_index)).unwrap_or_else(|_| {
        panic!(
            "Should build valid private key for validator index {}",
            validator_index
        )
    });

    Keypair {
        pk: PublicKey::from_secret_key(&sk),
        sk,
    }
}

#[derive(Serialize, Deserialize)]
struct YamlKeypair {
    /// Big-endian.
    privkey: String,
    /// Big-endian.
    pubkey: String,
}

impl TryInto<Keypair> for YamlKeypair {
    type Error = String;

    fn try_into(self) -> Result<Keypair, Self::Error> {
        let privkey = string_to_bytes(&self.privkey)?;
        let pubkey = string_to_bytes(&self.pubkey)?;

        if (privkey.len() > PRIVATE_KEY_BYTES) || (pubkey.len() > PUBLIC_KEY_BYTES) {
            return Err("Public or private key is too long".into());
        }

        let sk = {
            let mut bytes = vec![0; PRIVATE_KEY_BYTES - privkey.len()];
            bytes.extend_from_slice(&privkey);
            SecretKey::from_bytes(&bytes)
                .map_err(|e| format!("Failed to decode bytes into secret key: {:?}", e))?
        };

        let pk = {
            let mut bytes = vec![0; PUBLIC_KEY_BYTES - pubkey.len()];
            bytes.extend_from_slice(&pubkey);
            PublicKey::from_bytes(&bytes)
                .map_err(|e| format!("Failed to decode bytes into public key: {:?}", e))?
        };

        Ok(Keypair { pk, sk })
    }
}

fn string_to_bytes(string: &str) -> Result<Vec<u8>, String> {
    let string = if string.starts_with("0x") {
        &string[2..]
    } else {
        string
    };

    hex::decode(string).map_err(|e| format!("Unable to decode public or private key: {}", e))
}

/// Loads keypairs from a YAML encoded file.
///
/// Uses this as reference:
/// https://github.com/ethereum/eth2.0-pm/blob/9a9dbcd95e2b8e10287797bd768014ab3d842e99/interop/mocked_start/keygen_10_validators.yaml
pub fn keypairs_from_yaml_file(path: PathBuf) -> Result<Vec<Keypair>, String> {
    let file =
        File::open(path.clone()).map_err(|e| format!("Unable to open YAML key file: {}", e))?;

    serde_yaml::from_reader::<_, Vec<YamlKeypair>>(file)
        .map_err(|e| format!("Could not parse YAML: {:?}", e))?
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<Vec<_>, String>>()
}
