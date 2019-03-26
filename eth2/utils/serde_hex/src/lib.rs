use hex;
use hex::ToHex;
use serde::de::{self, Visitor};
use std::fmt;

pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
    let mut hex = String::with_capacity(data.as_ref().len() * 2);

    // Writing to a string never errors, so we can unwrap here.
    data.write_hex(&mut hex).unwrap();

    let mut s = "0x".to_string();

    s.push_str(hex.as_str());

    s
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
        if value.starts_with("0x") {
            Ok(hex::decode(&value[2..])
                .map_err(|e| de::Error::custom(format!("invalid hex ({:?})", e)))?)
        } else {
            Err(de::Error::custom("missing 0x prefix"))
        }
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
        Ok(hex::decode(value.trim_start_matches("0x"))
            .map_err(|e| de::Error::custom(format!("invalid hex ({:?})", e)))?)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encoding() {
        let bytes = vec![0, 255];
        let hex = encode(&bytes);
        assert_eq!(hex.as_str(), "0x00ff");

        let bytes = vec![];
        let hex = encode(&bytes);
        assert_eq!(hex.as_str(), "0x");

        let bytes = vec![1, 2, 3];
        let hex = encode(&bytes);
        assert_eq!(hex.as_str(), "0x010203");
    }
}
