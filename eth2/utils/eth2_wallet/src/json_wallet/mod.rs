use serde::{Deserialize, Serialize};
use serde_repr::*;
use std::convert::TryFrom;

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
    #[serde(rename = "type")]
    pub type_field: TypeField,
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

/// Used for ensuring that serde only decodes valid checksum functions.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum TypeField {
    Hd,
}

impl Into<String> for TypeField {
    fn into(self) -> String {
        match self {
            TypeField::Hd => "hierarchical deterministic".into(),
        }
    }
}

impl TryFrom<String> for TypeField {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_ref() {
            "hierarchical deterministic" => Ok(TypeField::Hd),
            other => Err(format!("Unsupported type function: {}", other)),
        }
    }
}
