//! Formats `u32` as a 0x-prefixed, little-endian hex string.
//!
//! E.g., `0` serializes as `"0x00000000"`.

use crate::bytes_4_hex;
use serde::{Deserializer, Serializer};

pub fn serialize<S>(num: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex = format!("0x{}", hex::encode(num.to_le_bytes()));
    serializer.serialize_str(&hex)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    bytes_4_hex::deserialize(deserializer).map(u32::from_le_bytes)
}
