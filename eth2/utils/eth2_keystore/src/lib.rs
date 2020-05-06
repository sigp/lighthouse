//! Provides a JSON keystore for a BLS keypair, as specified by
//! [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).

mod derived_key;
mod keystore;
mod lamport_secret_key;
mod password;
mod path;
mod plain_text;

pub mod json_keystore;

pub use keystore::{Error, Keystore, KeystoreBuilder};
pub use password::Password;
pub use path::MasterKey;
pub use uuid::Uuid;
