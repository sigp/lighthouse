//! Provides a JSON keystore for a BLS keypair, as specified by
//! [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).

mod derived_key;
mod keystore;
mod plain_text;

pub mod json_keystore;

pub use keystore::{
    decrypt, default_kdf, encrypt, keypair_from_secret, Error, Keystore, KeystoreBuilder, DKLEN,
    HASH_SIZE, IV_SIZE, SALT_SIZE,
};
pub use plain_text::PlainText;
pub use uuid::Uuid;
