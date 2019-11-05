use crypto::digest::Digest;
use crypto::sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ChecksumModule {
    pub function: String,
    pub params: BTreeMap<(), ()>, // TODO: need a better way to encode empty json object
    pub message: String,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Checksum(String);

impl Checksum {
    pub fn gen_checksum(message: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.input(message);
        hasher.result_str()
    }

    pub fn function() -> String {
        "sha256".to_string()
    }
}
