use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

macro_rules! define_mod {
    ($int: ty, $serialize_func:path) => {
        pub fn serialize<S>(value: &Option<$int>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match value {
                Some(inner) => $serialize_func(inner, serializer),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<$int>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt: Option<String> = Option::deserialize(deserializer)?;
            match opt {
                Some(val) => {
                    let int_val = serde_json::from_str::<$int>(&val).map_err(Error::custom)?;
                    Ok(Some(int_val))
                }
                None => Ok(None),
            }
        }

        #[cfg(test)]
        mod test {
            use serde::{Deserialize, Serialize};

            #[derive(Debug, PartialEq, Serialize, Deserialize)]
            #[serde(transparent)]
            struct WrappedOptionInt(#[serde(with = "super")] Option<$int>);

            #[test]
            fn option_quote_some() {
                assert_eq!(
                    &serde_json::to_string(&WrappedOptionInt(Some(42))).unwrap(),
                    "\"42\""
                );
                assert_eq!(
                    serde_json::from_str::<WrappedOptionInt>("\"42\"").unwrap(),
                    WrappedOptionInt(Some(42))
                );
            }

            #[test]
            fn option_quote_none() {
                assert_eq!(
                    &serde_json::to_string(&WrappedOptionInt(None)).unwrap(),
                    "null"
                );
                assert_eq!(
                    serde_json::from_str::<WrappedOptionInt>("null").unwrap(),
                    WrappedOptionInt(None)
                );
            }
        }
    };
}

pub mod option_quoted_u64 {
    use super::*;

    define_mod!(u64, serde_utils::quoted_u64::serialize);
}
