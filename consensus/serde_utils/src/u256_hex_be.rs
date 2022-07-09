use ethereum_types::U256;

use crate::u64_hex_be::QuantityVisitor;
use serde::de::Error;
use serde::{Deserializer, Serializer};

const BYTES_LEN: usize = 32;

pub fn serialize<S>(num: &U256, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut bytes = [0; BYTES_LEN];
    num.to_big_endian(&mut bytes);
    let raw = hex::encode(bytes);
    let trimmed = raw.trim_start_matches('0');

    let hex = if trimmed.is_empty() { "0" } else { trimmed };

    serializer.serialize_str(&format!("0x{}", &hex))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
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
    Ok(U256::from_big_endian(&array))
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
