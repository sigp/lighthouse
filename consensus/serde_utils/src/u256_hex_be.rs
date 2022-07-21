use ethereum_types::U256;

use serde::de::Visitor;
use serde::{de, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

pub fn serialize<S>(num: &U256, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    num.serialize(serializer)
}

pub struct U256Visitor;

impl<'de> Visitor<'de> for U256Visitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a well formatted hex string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if !value.starts_with("0x") {
            return Err(de::Error::custom("must start with 0x"));
        }
        let stripped = &value[2..];
        if stripped.is_empty() {
            Err(de::Error::custom(format!(
                "quantity cannot be {:?}",
                stripped
            )))
        } else if stripped == "0" {
            Ok(value.to_string())
        } else if stripped.starts_with('0') {
            Err(de::Error::custom("cannot have leading zero"))
        } else {
            Ok(value.to_string())
        }
    }
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let decoded = deserializer.deserialize_string(U256Visitor)?;

    U256::from_str(&decoded).map_err(|e| de::Error::custom(format!("Invalid U256 string: {}", e)))
}

#[cfg(test)]
mod test {
    use ethereum_types::U256;
    use serde::{Deserialize, Serialize};
    use serde_json;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(transparent)]
    struct Wrapper {
        #[serde(with = "super")]
        val: U256,
    }

    #[test]
    fn encoding() {
        assert_eq!(
            &serde_json::to_string(&Wrapper { val: 0.into() }).unwrap(),
            "\"0x0\""
        );
        assert_eq!(
            &serde_json::to_string(&Wrapper { val: 1.into() }).unwrap(),
            "\"0x1\""
        );
        assert_eq!(
            &serde_json::to_string(&Wrapper { val: 256.into() }).unwrap(),
            "\"0x100\""
        );
        assert_eq!(
            &serde_json::to_string(&Wrapper { val: 65.into() }).unwrap(),
            "\"0x41\""
        );
        assert_eq!(
            &serde_json::to_string(&Wrapper { val: 1024.into() }).unwrap(),
            "\"0x400\""
        );
        assert_eq!(
            &serde_json::to_string(&Wrapper {
                val: U256::max_value() - 1
            })
            .unwrap(),
            "\"0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\""
        );
        assert_eq!(
            &serde_json::to_string(&Wrapper {
                val: U256::max_value()
            })
            .unwrap(),
            "\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\""
        );
    }

    #[test]
    fn decoding() {
        assert_eq!(
            serde_json::from_str::<Wrapper>("\"0x0\"").unwrap(),
            Wrapper { val: 0.into() },
        );
        assert_eq!(
            serde_json::from_str::<Wrapper>("\"0x41\"").unwrap(),
            Wrapper { val: 65.into() },
        );
        assert_eq!(
            serde_json::from_str::<Wrapper>("\"0x400\"").unwrap(),
            Wrapper { val: 1024.into() },
        );
        assert_eq!(
            serde_json::from_str::<Wrapper>(
                "\"0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\""
            )
            .unwrap(),
            Wrapper {
                val: U256::max_value() - 1
            },
        );
        assert_eq!(
            serde_json::from_str::<Wrapper>(
                "\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\""
            )
            .unwrap(),
            Wrapper {
                val: U256::max_value()
            },
        );
        serde_json::from_str::<Wrapper>("\"0x\"").unwrap_err();
        serde_json::from_str::<Wrapper>("\"0x0400\"").unwrap_err();
        serde_json::from_str::<Wrapper>("\"400\"").unwrap_err();
        serde_json::from_str::<Wrapper>("\"ff\"").unwrap_err();
    }
}
