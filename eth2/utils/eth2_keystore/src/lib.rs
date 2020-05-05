//! Provides a JSON keystore for a BLS keypair, as specified by
//! [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).

mod derived_key;
mod json_keystore;
mod keystore;
mod password;
mod plain_text;

pub use keystore::{Error, Keystore, KeystoreBuilder};
pub use password::Password;
pub use uuid::Uuid;
