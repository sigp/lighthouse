//! Provides path-based hierarchical BLS key derivation, as specified by
//! [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333).

mod derived_key;
mod lamport_secret_key;
mod plain_text;
mod secret_bytes;

pub use bls::SecretHash;
pub use derived_key::DerivedKey;
pub use plain_text::PlainText;
