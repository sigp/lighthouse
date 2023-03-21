//! Provides utilities for parsing 0x-prefixed hex strings.

use serde::de::{self, Visitor};
use std::fmt;

/// Encode `data` as a 0x-prefixed hex string.
pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
    let hex = hex::encode(data);

    let mut s = "0x".to_string();
    s.push_str(hex.as_str());
    s
}

/// Decode `data` from a 0x-prefixed hex string.
pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    if let Some(stripped) = s.strip_prefix("0x") {
        hex::decode(stripped).map_err(|e| format!("invalid hex: {:?}", e))
    } else {
        Err("hex must have 0x prefix".to_string())
    }
}

pub struct PrefixedHexVisitor;

impl<'de> Visitor<'de> for PrefixedHexVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a hex string with 0x prefix")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        decode(value).map_err(de::Error::custom)
    }
}

pub struct HexVisitor;

impl<'de> Visitor<'de> for HexVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a hex string (irrelevant of prefix)")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        hex::decode(value.trim_start_matches("0x"))
            .map_err(|e| de::Error::custom(format!("invalid hex ({:?})", e)))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encoding() {
        let bytes = vec![0, 255];
        let hex = encode(bytes);
        assert_eq!(hex.as_str(), "0x00ff");

        let bytes = vec![];
        let hex = encode(bytes);
        assert_eq!(hex.as_str(), "0x");

        let bytes = vec![1, 2, 3];
        let hex = encode(bytes);
        assert_eq!(hex.as_str(), "0x010203");
    }
}
