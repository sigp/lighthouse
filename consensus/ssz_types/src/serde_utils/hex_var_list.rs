//! Serialize `VariableList<u8, N>` as 0x-prefixed hex string.
use crate::VariableList;
use eth2_serde_utils::hex::{self, PrefixedHexVisitor};
use serde::{Deserializer, Serializer};
use typenum::Unsigned;

pub fn serialize<S, N>(bytes: &VariableList<u8, N>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    N: Unsigned,
{
    serializer.serialize_str(&hex::encode(&**bytes))
}

pub fn deserialize<'de, D, N>(deserializer: D) -> Result<VariableList<u8, N>, D::Error>
where
    D: Deserializer<'de>,
    N: Unsigned,
{
    let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
    VariableList::new(bytes)
        .map_err(|e| serde::de::Error::custom(format!("invalid variable list: {:?}", e)))
}
