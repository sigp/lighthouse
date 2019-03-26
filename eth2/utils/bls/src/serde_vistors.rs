use hex;
use serde::de::{self, Visitor};
use std::fmt;

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
