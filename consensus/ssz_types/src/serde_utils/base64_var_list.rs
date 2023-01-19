//! Serialize `VariableList<u8, N>` as a base64 string.
use crate::VariableList;
use base64;
use serde::{Deserializer, Serializer};
use serde_with::{
    base64::{Base64, Standard},
    DeserializeAs,
};
use typenum::Unsigned;

pub fn serialize<S, N>(bytes: &VariableList<u8, N>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    N: Unsigned,
{
    serializer.serialize_str(&base64::encode(&**bytes))
}

pub fn deserialize<'de, D, N>(deserializer: D) -> Result<VariableList<u8, N>, D::Error>
where
    D: Deserializer<'de>,
    N: Unsigned,
{
    let bytes = Base64::<Standard>::deserialize_as(deserializer)?;
    VariableList::new(bytes)
        .map_err(|e| serde::de::Error::custom(format!("invalid variable list: {:?}", e)))
}
