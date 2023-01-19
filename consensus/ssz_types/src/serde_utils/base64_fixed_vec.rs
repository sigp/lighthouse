//! Serialize `FixedVec<u8, N>` as a base64 string.
use crate::FixedVector;
use base64;
use serde::{Deserializer, Serializer};
use serde_with::{
    base64::{Base64, Standard},
    DeserializeAs,
};
use typenum::Unsigned;

pub fn serialize<S, U>(bytes: &FixedVector<u8, U>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    U: Unsigned,
{
    serializer.serialize_str(&base64::encode(&bytes[..]))
}

pub fn deserialize<'de, D, U>(deserializer: D) -> Result<FixedVector<u8, U>, D::Error>
where
    D: Deserializer<'de>,
    U: Unsigned,
{
    let vec = Base64::<Standard>::deserialize_as(deserializer)?;
    FixedVector::new(vec)
        .map_err(|e| serde::de::Error::custom(format!("invalid fixed vector: {:?}", e)))
}
