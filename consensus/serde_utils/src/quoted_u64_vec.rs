use serde::ser::SerializeSeq;
use serde::{Deserializer, Serializer};
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct QuotedIntWrapper {
    #[serde(with = "crate::quoted_u64")]
    int: u64,
}

pub struct QuotedIntVecVisitor;
impl<'a> serde::de::Visitor<'a> for QuotedIntVecVisitor {
    type Value = Vec<u64>;

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

        Ok(vec)
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

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(QuotedIntVecVisitor)
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    struct Obj {
        #[serde(with = "crate::quoted_u64_vec")]
        values: Vec<u64>,
    }

    #[test]
    fn quoted_list_success() {
        let obj: Obj = serde_json::from_str(r#"{ "values": ["1", "2", "3", "4"] }"#).unwrap();
        assert_eq!(obj.values, vec![1, 2, 3, 4]);
    }

    #[test]
    fn unquoted_list_success() {
        let obj: Obj = serde_json::from_str(r#"{ "values": [1, 2, 3, 4] }"#).unwrap();
        assert_eq!(obj.values, vec![1, 2, 3, 4]);
    }

    #[test]
    fn mixed_list_success() {
        let obj: Obj = serde_json::from_str(r#"{ "values": ["1", 2, "3", "4"] }"#).unwrap();
        assert_eq!(obj.values, vec![1, 2, 3, 4]);
    }

    #[test]
    fn empty_list_success() {
        let obj: Obj = serde_json::from_str(r#"{ "values": [] }"#).unwrap();
        assert!(obj.values.is_empty());
    }

    #[test]
    fn whole_list_quoted_err() {
        serde_json::from_str::<Obj>(r#"{ "values": "[1, 2, 3, 4]" }"#).unwrap_err();
    }
}
