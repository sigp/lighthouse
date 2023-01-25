//! Serialize a datatype as a JSON-blob within a single string.
use serde::{
    de::{DeserializeOwned, Error as _},
    ser::Error as _,
    Deserialize, Deserializer, Serialize, Serializer,
};

/// Serialize as a JSON object within a string.
pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    serializer.serialize_str(&serde_json::to_string(value).map_err(S::Error::custom)?)
}

/// Deserialize a JSON object embedded in a string.
pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let json_str = String::deserialize(deserializer)?;
    serde_json::from_str(&json_str).map_err(D::Error::custom)
}
