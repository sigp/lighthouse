//! Defines the JSON representation of the "cipher" module.
//!
//! This file **MUST NOT** contain any logic beyond what is required to serialize/deserialize the
//! data structures. Specifically, there should not be any actual crypto logic in this file.

use super::hex_bytes::HexBytes;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// Used for ensuring that serde only decodes valid cipher functions.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum CipherFunction {
    Aes128Ctr,
}

impl Into<String> for CipherFunction {
    fn into(self) -> String {
        match self {
            CipherFunction::Aes128Ctr => "aes-128-ctr".into(),
        }
    }
}

impl TryFrom<String> for CipherFunction {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_ref() {
            "aes-128-ctr" => Ok(CipherFunction::Aes128Ctr),
            other => Err(format!("Unsupported cipher function: {}", other)),
        }
    }
}

/// Cipher module representation.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CipherModule {
    pub function: CipherFunction,
    pub params: Cipher,
    pub message: HexBytes,
}

/// Parameters for AES128 with ctr mode.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aes128Ctr {
    pub iv: HexBytes,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Cipher {
    Aes128Ctr(Aes128Ctr),
}

impl Cipher {
    pub fn function(&self) -> CipherFunction {
        match &self {
            Cipher::Aes128Ctr(_) => CipherFunction::Aes128Ctr,
        }
    }
}
