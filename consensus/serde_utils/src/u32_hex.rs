//! Formats `u32` as a 0x-prefixed, little-endian hex string.
//!
//! E.g., `0` serializes as `"0x00000000"`.

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S>(num: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut hex: String = "0x".to_string();
    let bytes = num.to_le_bytes();
    hex.push_str(&hex::encode(&bytes));

    serializer.serialize_str(&hex)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let start = s
        .as_str()
        .get(2..)
        .ok_or_else(|| D::Error::custom("string length too small"))?;

    u32::from_str_radix(&start, 16)
        .map_err(D::Error::custom)
        .map(u32::from_be)
}
