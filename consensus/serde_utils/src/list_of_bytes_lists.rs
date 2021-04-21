//! Formats `Vec<u64>` using quotes.
//!
//! E.g., `vec![0, 1, 2]` serializes as `["0", "1", "2"]`.
//!
//! Quotes can be optional during decoding.

use crate::hex;
use serde::ser::SerializeSeq;
use serde::{de, Deserializer, Serializer};

pub struct ListOfBytesListVisitor;
impl<'a> serde::de::Visitor<'a> for ListOfBytesListVisitor {
    type Value = Vec<Vec<u8>>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a list of 0x-prefixed byte lists")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'a>,
    {
        let mut vec = vec![];

        while let Some(val) = seq.next_element::<String>()? {
            vec.push(hex::decode(&val).map_err(de::Error::custom)?);
        }

        Ok(vec)
    }
}

pub fn serialize<S>(value: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(value.len()))?;
    for val in value {
        seq.serialize_element(&hex::encode(val))?;
    }
    seq.end()
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(ListOfBytesListVisitor)
}
