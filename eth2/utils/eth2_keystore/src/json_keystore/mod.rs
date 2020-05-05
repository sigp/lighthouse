mod checksum_module;
mod cipher_module;
mod hex_bytes;
mod kdf_module;

pub use checksum_module::{ChecksumModule, EmptyMap, Sha256Checksum};
pub use cipher_module::{Aes128Ctr, Cipher, CipherModule};
pub use hex_bytes::HexBytes;
pub use kdf_module::{Kdf, KdfModule, Pbkdf2, Prf};
pub use uuid::Uuid;

use serde::{Deserialize, Serialize};
use serde_repr::*;

/// JSON representation of [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335) keystore.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonKeystore {
    pub crypto: Crypto,
    pub uuid: Uuid,
    pub path: String,
    pub pubkey: String,
    pub version: Version,
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
pub struct Crypto {
    pub kdf: KdfModule,
    pub checksum: ChecksumModule,
    pub cipher: CipherModule,
}
