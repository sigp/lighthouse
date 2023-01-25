//! Formats `u64` as a 0x-prefixed, big-endian hex string.
//!
//! E.g., `0` serializes as `"0x0000000000000000"`.

use serde::de::{self, Error, Visitor};
use serde::{Deserializer, Serializer};
use std::fmt;

const BYTES_LEN: usize = 8;

pub struct QuantityVisitor;
impl<'de> Visitor<'de> for QuantityVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a hex string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if !value.starts_with("0x") {
            return Err(de::Error::custom("must start with 0x"));
        }

        let stripped = value.trim_start_matches("0x");

        if stripped.is_empty() {
            Err(de::Error::custom(format!(
                "quantity cannot be {}",
                stripped
            )))
        } else if stripped == "0" {
            Ok(vec![0])
        } else if stripped.starts_with('0') {
            Err(de::Error::custom("cannot have leading zero"))
        } else if stripped.len() % 2 != 0 {
            hex::decode(format!("0{}", stripped))
                .map_err(|e| de::Error::custom(format!("invalid hex ({:?})", e)))
        } else {
            hex::decode(stripped).map_err(|e| de::Error::custom(format!("invalid hex ({:?})", e)))
        }
    }
}

pub fn serialize<S>(num: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let raw = hex::encode(num.to_be_bytes());
    let trimmed = raw.trim_start_matches('0');

    let hex = if trimmed.is_empty() { "0" } else { trimmed };

    serializer.serialize_str(&format!("0x{}", &hex))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let decoded = deserializer.deserialize_str(QuantityVisitor)?;

    // TODO: this is not strict about byte length like other methods.
    if decoded.len() > BYTES_LEN {
        return Err(D::Error::custom(format!(
            "expected max {} bytes for array, got {}",
            BYTES_LEN,
            decoded.len()
        )));
    }

    let mut array = [0; BYTES_LEN];
    array[BYTES_LEN - decoded.len()..].copy_from_slice(&decoded);
    Ok(u64::from_be_bytes(array))
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};
    use serde_json;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(transparent)]
    struct Wrapper {
        #[serde(with = "super")]
        val: u64,
    }

    #[test]
    fn encoding() {
        assert_eq!(
            &serde_json::to_string(&Wrapper { val: 0 }).unwrap(),
            "\"0x0\""
        );
        assert_eq!(
            &serde_json::to_string(&Wrapper { val: 1 }).unwrap(),
            "\"0x1\""
        );
        assert_eq!(
            &serde_json::to_string(&Wrapper { val: 256 }).unwrap(),
            "\"0x100\""
        );
        assert_eq!(
            &serde_json::to_string(&Wrapper { val: 65 }).unwrap(),
            "\"0x41\""
        );
        assert_eq!(
            &serde_json::to_string(&Wrapper { val: 1024 }).unwrap(),
            "\"0x400\""
        );
    }

    #[test]
    fn decoding() {
        assert_eq!(
            serde_json::from_str::<Wrapper>("\"0x0\"").unwrap(),
            Wrapper { val: 0 },
        );
        assert_eq!(
            serde_json::from_str::<Wrapper>("\"0x41\"").unwrap(),
            Wrapper { val: 65 },
        );
        assert_eq!(
            serde_json::from_str::<Wrapper>("\"0x400\"").unwrap(),
            Wrapper { val: 1024 },
        );
        serde_json::from_str::<Wrapper>("\"0x\"").unwrap_err();
        serde_json::from_str::<Wrapper>("\"0x0400\"").unwrap_err();
        serde_json::from_str::<Wrapper>("\"400\"").unwrap_err();
        serde_json::from_str::<Wrapper>("\"ff\"").unwrap_err();
    }
}
