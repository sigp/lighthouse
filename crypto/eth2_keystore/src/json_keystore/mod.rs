//! This module intends to separate the JSON representation of the keystore from the actual crypto
//! logic.
//!
//! This module **MUST NOT** contain any logic beyond what is required to serialize/deserialize the
//! data structures. Specifically, there should not be any actual crypto logic in this file.

mod checksum_module;
mod cipher_module;
mod hex_bytes;
mod kdf_module;

pub use checksum_module::{ChecksumModule, EmptyMap, Sha256Checksum};
pub use cipher_module::{Aes128Ctr, Cipher, CipherModule};
pub use hex_bytes::HexBytes;
pub use kdf_module::{EmptyString, Kdf, KdfModule, Pbkdf2, Prf, Scrypt};
pub use uuid::Uuid;

use serde::{Deserialize, Serialize};
use serde_repr::*;

/// JSON representation of [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335) keystore.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonKeystore {
    pub crypto: Crypto,
    pub uuid: Uuid,
    /// EIP-2335 does not declare this field as optional, but Prysm is omitting it so we must
    /// support it.
    pub path: Option<String>,
    pub pubkey: String,
    pub version: Version,
    pub description: Option<String>,
    /// Not part of EIP-2335, but `ethdo` and Prysm have adopted it anyway so we must support it.
    pub name: Option<String>,
}

/// Version for `JsonKeystore`.
#[derive(Debug, Clone, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Version {
    V4 = 4,
}

impl Version {
    pub fn four() -> Self {
        Version::V4
    }
}

/// Crypto module for keystore.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Crypto {
    pub kdf: KdfModule,
    pub checksum: ChecksumModule,
    pub cipher: CipherModule,
}
