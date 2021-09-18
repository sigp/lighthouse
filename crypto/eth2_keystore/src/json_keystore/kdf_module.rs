//! Defines the JSON representation of the "kdf" module.
//!
//! This file **MUST NOT** contain any logic beyond what is required to serialize/deserialize the
//! data structures. Specifically, there should not be any actual crypto logic in this file.

use super::hex_bytes::HexBytes;
use crate::DKLEN;
use hmac::{Hmac, Mac, NewMac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::convert::TryFrom;

/// KDF module representation.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfModule {
    pub function: KdfFunction,
    pub params: Kdf,
    pub message: EmptyString,
}

/// Used for ensuring serde only decodes an empty string.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EmptyString;

impl Into<String> for EmptyString {
    fn into(self) -> String {
        "".into()
    }
}

impl TryFrom<String> for EmptyString {
    type Error = &'static str;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_ref() {
            "" => Ok(Self),
            _ => Err("kdf message must be empty"),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Kdf {
    Scrypt(Scrypt),
    Pbkdf2(Pbkdf2),
}

impl Kdf {
    pub fn function(&self) -> KdfFunction {
        match &self {
            Kdf::Pbkdf2(_) => KdfFunction::Pbkdf2,
            Kdf::Scrypt(_) => KdfFunction::Scrypt,
        }
    }
}

/// PRF for use in `pbkdf2`.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Prf {
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
}

impl Prf {
    pub fn mac(&self, password: &[u8]) -> impl Mac {
        match &self {
            Prf::HmacSha256 => Hmac::<Sha256>::new_from_slice(password)
                .expect("Could not derive HMAC using SHA256."),
        }
    }
}

impl Default for Prf {
    fn default() -> Self {
        Prf::HmacSha256
    }
}

/// Parameters for `pbkdf2` key derivation.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pbkdf2 {
    pub c: u32,
    pub dklen: u32,
    pub prf: Prf,
    pub salt: HexBytes,
}

/// Used for ensuring that serde only decodes valid KDF functions.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum KdfFunction {
    Scrypt,
    Pbkdf2,
}

impl Into<String> for KdfFunction {
    fn into(self) -> String {
        match self {
            KdfFunction::Scrypt => "scrypt".into(),
            KdfFunction::Pbkdf2 => "pbkdf2".into(),
        }
    }
}

impl TryFrom<String> for KdfFunction {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_ref() {
            "scrypt" => Ok(KdfFunction::Scrypt),
            "pbkdf2" => Ok(KdfFunction::Pbkdf2),
            other => Err(format!("Unsupported kdf function: {}", other)),
        }
    }
}

/// Parameters for `scrypt` key derivation.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scrypt {
    pub dklen: u32,
    pub n: u32,
    pub r: u32,
    pub p: u32,
    pub salt: HexBytes,
}

impl Scrypt {
    pub fn default_scrypt(salt: Vec<u8>) -> Self {
        Self {
            dklen: DKLEN,
            n: 262144,
            p: 1,
            r: 8,
            salt: salt.into(),
        }
    }
}
