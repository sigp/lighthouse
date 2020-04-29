use crate::kdf::DerivedKey;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use serde::{Deserialize, Serialize};

/// Checksum module for `Keystore`.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ChecksumModule {
    pub function: String,
    pub params: serde_json::Value, // Empty json object
    pub message: String,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Sha256Checksum(String);

impl Sha256Checksum {
    pub fn generate(derived_key: &DerivedKey, cipher_message: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.input(derived_key.checksum_slice());
        hasher.input(cipher_message);
        hasher.result_str()
    }

    pub fn function() -> String {
        "sha256".to_string()
    }
}
