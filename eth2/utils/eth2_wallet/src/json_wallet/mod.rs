use serde::{Deserialize, Serialize};
use serde_repr::*;

pub use eth2_keystore::json_keystore::{
    Aes128Ctr, ChecksumModule, Cipher, CipherModule, Crypto, EmptyMap, EmptyString, Kdf, KdfModule,
    Scrypt, Sha256Checksum,
};
pub use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonWallet {
    pub crypto: Crypto,
    pub name: String,
    pub nextaccount: u32,
    pub uuid: Uuid,
    pub version: Version,
}

/// Version for `JsonWallet`.
#[derive(Debug, Clone, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Version {
    V1 = 1,
}

impl Version {
    pub fn one() -> Self {
        Version::V1
    }
}
