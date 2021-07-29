//! Formats `FixedVector<u64,N>` using quotes.
//!
//! E.g., `FixedVector::from(vec![0, 1, 2])` serializes as `["0", "1", "2"]`.
//!
//! Quotes can be optional during decoding. If `N` does not equal the length deserialization will fail.

use crate::serde_utils::quoted_u64_var_list::deserialize_max;
use crate::FixedVector;
use eth2_serde_utils::quoted_u64_vec::QuotedIntWrapper;
use serde::ser::SerializeSeq;
use serde::{Deserializer, Serializer};
use std::marker::PhantomData;
use typenum::Unsigned;

pub struct QuotedIntFixedVecVisitor<N> {
    _phantom: PhantomData<N>,
}

impl<'a, N> serde::de::Visitor<'a> for QuotedIntFixedVecVisitor<N>
where
    N: Unsigned,
{
    type Value = FixedVector<u64, N>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a list of quoted or unquoted integers")
    }

    fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'a>,
    {
        let vec = deserialize_max(seq, N::to_usize())?;
        let fix: FixedVector<u64, N> = FixedVector::new(vec)
            .map_err(|e| serde::de::Error::custom(format!("FixedVector: {:?}", e)))?;
        Ok(fix)
    }
}

pub fn serialize<S>(value: &[u64], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(value.len()))?;
    for &int in value {
        seq.serialize_element(&QuotedIntWrapper { int })?;
    }
    seq.end()
}

pub fn deserialize<'de, D, N>(deserializer: D) -> Result<FixedVector<u64, N>, D::Error>
where
    D: Deserializer<'de>,
    N: Unsigned,
{
    deserializer.deserialize_any(QuotedIntFixedVecVisitor {
        _phantom: PhantomData,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_derive::{Deserialize, Serialize};
    use typenum::U4;

    #[derive(Debug, Serialize, Deserialize)]
    struct Obj {
        #[serde(with = "crate::serde_utils::quoted_u64_fixed_vec")]
        values: FixedVector<u64, U4>,
    }

    #[test]
    fn quoted_list_success() {
        let obj: Obj = serde_json::from_str(r#"{ "values": ["1", "2", "3", "4"] }"#).unwrap();
        let expected: FixedVector<u64, U4> = FixedVector::from(vec![1, 2, 3, 4]);
        assert_eq!(obj.values, expected);
    }

    #[test]
    fn unquoted_list_success() {
        let obj: Obj = serde_json::from_str(r#"{ "values": [1, 2, 3, 4] }"#).unwrap();
        let expected: FixedVector<u64, U4> = FixedVector::from(vec![1, 2, 3, 4]);
        assert_eq!(obj.values, expected);
    }

    #[test]
    fn mixed_list_success() {
        let obj: Obj = serde_json::from_str(r#"{ "values": ["1", 2, "3", "4"] }"#).unwrap();
        let expected: FixedVector<u64, U4> = FixedVector::from(vec![1, 2, 3, 4]);
        assert_eq!(obj.values, expected);
    }

    #[test]
    fn empty_list_err() {
        serde_json::from_str::<Obj>(r#"{ "values": [] }"#).unwrap_err();
    }

    #[test]
    fn short_list_err() {
        serde_json::from_str::<Obj>(r#"{ "values": [1, 2] }"#).unwrap_err();
    }

    #[test]
    fn long_list_err() {
        serde_json::from_str::<Obj>(r#"{ "values": [1, 2, 3, 4, 5] }"#).unwrap_err();
    }

    #[test]
    fn whole_list_quoted_err() {
        serde_json::from_str::<Obj>(r#"{ "values": "[1, 2, 3, 4]" }"#).unwrap_err();
    }
}
