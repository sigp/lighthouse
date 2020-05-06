//! Provides a JSON keystore for a BLS keypair, as specified by
//! [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).

mod lamport_secret_key;
mod path;

pub use path::DerivedKey;
