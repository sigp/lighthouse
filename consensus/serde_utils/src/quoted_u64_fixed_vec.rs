//! Formats `FixedVector<u64,N>` using quotes.
//!
//! E.g., `FixedVector::from(vec![0, 1, 2])` serializes as `["0", "1", "2"]`.
//!
//! Quotes can be optional during decoding. If `N` does not equal the length of the `Vec`, the `Vec` is truncated.

use serde::ser::SerializeSeq;
use serde::{Deserializer, Serializer};
use serde_derive::{Deserialize, Serialize};
use ssz_types::typenum::Unsigned;
use ssz_types::FixedVector;
use std::marker::PhantomData;

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct QuotedIntWrapper {
    #[serde(with = "crate::quoted_u64")]
    pub int: u64,
}

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

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'a>,
    {
        let mut vec = vec![];

        while let Some(val) = seq.next_element()? {
            let val: QuotedIntWrapper = val;
            vec.push(val.int);
        }
        let fix: FixedVector<u64, N> = FixedVector::from(vec);
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
    use ssz_types::typenum::U4;

    #[derive(Debug, Serialize, Deserialize)]
    struct Obj {
        #[serde(with = "crate::quoted_u64_fixed_vec")]
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
    fn empty_list_success() {
        let obj: Obj = serde_json::from_str(r#"{ "values": [] }"#).unwrap();
        let expected: FixedVector<u64, U4> = FixedVector::from(vec![0, 0, 0, 0]);
        assert_eq!(obj.values, expected);
    }

    #[test]
    fn short_list_success() {
        let obj: Obj = serde_json::from_str(r#"{ "values": [1, 2] }"#).unwrap();
        let expected: FixedVector<u64, U4> = FixedVector::from(vec![1, 2, 0, 0]);
        assert_eq!(obj.values, expected);
    }

    #[test]
    fn long_list_success() {
        let obj: Obj = serde_json::from_str(r#"{ "values": [1, 2, 3, 4, 5] }"#).unwrap();
        dbg!(&obj.values);
        let expected: FixedVector<u64, U4> = FixedVector::from(vec![1, 2, 3, 4]);
        assert_eq!(obj.values, expected);
    }

    #[test]
    fn whole_list_quoted_err() {
        serde_json::from_str::<Obj>(r#"{ "values": "[1, 2, 3, 4]" }"#).unwrap_err();
    }
}
