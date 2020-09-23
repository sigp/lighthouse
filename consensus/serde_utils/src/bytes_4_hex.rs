//! Formats `[u8; 4]` as a 0x-prefixed hex string.
//!
//! E.g., `[0, 1, 2, 3]` serializes as `"0x00010203"`.

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

const BYTES_LEN: usize = 4;

pub fn serialize<S>(bytes: &[u8; BYTES_LEN], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut hex_string: String = "0x".to_string();
    hex_string.push_str(&hex::encode(&bytes));

    serializer.serialize_str(&hex_string)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; BYTES_LEN], D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let mut array = [0 as u8; BYTES_LEN];

    let start = s
        .as_str()
        .get(2..)
        .ok_or_else(|| D::Error::custom("string length too small"))?;
    let decoded: Vec<u8> = hex::decode(&start).map_err(D::Error::custom)?;

    if decoded.len() != BYTES_LEN {
        return Err(D::Error::custom("Fork length too long"));
    }

    for (i, item) in array.iter_mut().enumerate() {
        if i > decoded.len() {
            break;
        }
        *item = decoded[i];
    }
    Ok(array)
}
