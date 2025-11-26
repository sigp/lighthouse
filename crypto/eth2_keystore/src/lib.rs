//! Provides a JSON keystore for a BLS keypair, as specified by
//! [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).

mod derived_key;
mod keystore;

pub mod json_keystore;

pub use bls::ZeroizeHash;
pub use eth2_key_derivation::PlainText;
pub use keystore::{
    DKLEN, Error, HASH_SIZE, IV_SIZE, Keystore, KeystoreBuilder, SALT_SIZE, decrypt, default_kdf,
    encrypt, keypair_from_secret,
};
pub use uuid::Uuid;
