//! Formats `u8` as a 0x-prefixed hex string.
//!
//! E.g., `0` serializes as `"0x00"`.

use crate::hex::PrefixedHexVisitor;
use serde::de::Error;
use serde::{Deserializer, Serializer};

pub fn serialize<S>(byte: &u8, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex = format!("0x{}", hex::encode([*byte]));
    serializer.serialize_str(&hex)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
    if bytes.len() != 1 {
        return Err(D::Error::custom(format!(
            "expected 1 byte for u8, got {}",
            bytes.len()
        )));
    }
    Ok(bytes[0])
}
