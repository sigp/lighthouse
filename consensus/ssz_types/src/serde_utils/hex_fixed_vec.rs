use crate::FixedVector;
use eth2_serde_utils::hex::{self, PrefixedHexVisitor};
use serde::{Deserializer, Serializer};
use typenum::Unsigned;

pub fn serialize<S, U>(bytes: &FixedVector<u8, U>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    U: Unsigned,
{
    let mut hex_string: String = "0x".to_string();
    hex_string.push_str(&hex::encode(&bytes[..]));

    serializer.serialize_str(&hex_string)
}

pub fn deserialize<'de, D, U>(deserializer: D) -> Result<FixedVector<u8, U>, D::Error>
where
    D: Deserializer<'de>,
    U: Unsigned,
{
    let vec = deserializer.deserialize_string(PrefixedHexVisitor)?;
    FixedVector::new(vec)
        .map_err(|e| serde::de::Error::custom(format!("invalid fixed vector: {:?}", e)))
}
