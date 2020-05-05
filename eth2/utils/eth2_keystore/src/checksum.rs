use crate::kdf::DerivedKey;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::convert::TryFrom;

/// Used for ensuring that serde only decodes valid checksum functions.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum ChecksumFunction {
    Sha256,
}

impl Into<String> for ChecksumFunction {
    fn into(self) -> String {
        match self {
            ChecksumFunction::Sha256 => "sha256".into(),
        }
    }
}

impl TryFrom<String> for ChecksumFunction {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_ref() {
            "sha256" => Ok(ChecksumFunction::Sha256),
            other => Err(format!("Unsupported checksum function: {}", other)),
        }
    }
}

/// Used for ensuring serde only decode an empty map
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "Value", into = "Value")]
pub struct EmptyMap;

impl Into<Value> for EmptyMap {
    fn into(self) -> Value {
        Value::Object(Map::default())
    }
}

impl TryFrom<Value> for EmptyMap {
    type Error = &'static str;

    fn try_from(v: Value) -> Result<Self, Self::Error> {
        match v {
            Value::Object(map) if map.is_empty() => Ok(Self),
            _ => Err("Checksum params must be an empty map"),
        }
    }
}

/// Checksum module for `Keystore`.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ChecksumModule {
    pub function: ChecksumFunction,
    pub params: EmptyMap,
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

    pub fn function() -> ChecksumFunction {
        ChecksumFunction::Sha256
    }
}
