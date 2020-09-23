//! Formats `u8` as a 0x-prefixed hex string.
//!
//! E.g., `0` serializes as `"0x00"`.

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S>(byte: &u8, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut hex: String = "0x".to_string();
    hex.push_str(&hex::encode(&[*byte]));

    serializer.serialize_str(&hex)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;

    let start = match s.as_str().get(2..) {
        Some(start) => start,
        None => return Err(D::Error::custom("string length too small")),
    };
    u8::from_str_radix(&start, 16).map_err(D::Error::custom)
}
