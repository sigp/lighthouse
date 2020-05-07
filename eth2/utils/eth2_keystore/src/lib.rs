//! Provides a JSON keystore for a BLS keypair, as specified by
//! [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).

mod derived_key;
mod keystore;
mod password;
mod plain_text;

pub mod json_keystore;

pub use keystore::{decrypt, encrypt, Error, Keystore, KeystoreBuilder};
pub use password::Password;
pub use uuid::Uuid;
