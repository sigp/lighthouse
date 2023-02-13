//! Formats `Vec<u8>` as a 0x-prefixed hex string.
//!
//! E.g., `vec![0, 1, 2, 3]` serializes as `"0x00010203"`.

use crate::hex::PrefixedHexVisitor;
use serde::{Deserializer, Serializer};

pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut hex_string: String = "0x".to_string();
    hex_string.push_str(&hex::encode(bytes));

    serializer.serialize_str(&hex_string)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_str(PrefixedHexVisitor)
}
